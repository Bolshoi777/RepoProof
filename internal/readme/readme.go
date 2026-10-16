// Package readme extracts candidate shell commands from fenced Markdown
// code blocks (G1-03, RP-003) using only the standard library.
//
// The parser is intentionally narrow: Markdown code blocks (fenced or
// indented), allowlisted command languages, one logical command per entry
// with 1-based file line spans. Everything else is skipped, never executed.
//
// Known limitations (honest non-goals):
//   - nested Markdown constructs beyond blockquote prefixes are not modeled;
//   - content lines that look like fence markup are skipped (structure,
//     not commands);
//   - heading->phase mapping is a keyword heuristic, not understanding;
//   - comment-only (#) and blank lines inside command blocks are skipped.
package readme

import (
	"fmt"
	"strings"
)

// MaxReadmeBytes bounds how much input Parse accepts.
const MaxReadmeBytes = 4 << 20 // 4 MiB

// Phases for the heading-context heuristic.
const (
	PhaseInstall = "install"
	PhaseLaunch  = "launch"
	PhaseVerify  = "verify"
	PhaseUnknown = "unknown"
)

// CandidateStep is one logical shell command with its source span.
type CandidateStep struct {
	ID         string `json:"id"`
	SourceFile string `json:"source_file"`
	LineStart  int    `json:"line_start"`
	LineEnd    int    `json:"line_end"`
	FenceStart int    `json:"fence_start"`
	FenceEnd   int    `json:"fence_end"`
	Language   string `json:"language"`
	Heading    string `json:"heading"`
	Phase      string `json:"phase"`
	Command    string `json:"command"`
	Unclosed   bool   `json:"unclosed"`
}

// ParseResult is the outcome of parsing one Markdown document.
type ParseResult struct {
	Steps         []CandidateStep `json:"steps"`
	Blocks        int             `json:"blocks"`
	SkippedBlocks int             `json:"skipped_blocks"`
}

// commandLangs allowlists fence info strings treated as shell commands.
// Empty info string means "plain block", the most common command style.
var commandLangs = map[string]bool{
	"": true, "sh": true, "bash": true, "shell": true,
	"console": true, "shell-session": true, "terminal": true,
	"cmd": true, "bat": true, "batch": true,
	"powershell": true, "ps1": true, "pwsh": true,
}

// sessionLangs use interactive prompts that must be stripped.
var sessionLangs = map[string]bool{
	"console": true, "shell-session": true, "terminal": true,
}

type fenceBlock struct {
	openLine   int // 1-based opening fence line
	closeLine  int // 1-based closing fence line (EOF line if unclosed)
	language   string
	unclosed   bool
	indented   bool
	blockquote bool
	content    []fenceLine
}

type fenceLine struct {
	no   int // 1-based file line number
	text string
}

// Parse extracts candidate commands from data. It never executes anything.
func Parse(sourceFile string, data []byte) (*ParseResult, error) {
	if len(data) > MaxReadmeBytes {
		return nil, fmt.Errorf("readme: %s exceeds %d bytes", sourceFile, MaxReadmeBytes)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1] // trailing element after final newline is not a line
	}
	blocks := []fenceBlock{}
	var cur *fenceBlock
	var fenceChar byte
	var fenceLen int

	for i, raw := range lines {
		no := i + 1
		if cur != nil && cur.indented {
			line := raw
			if cur.blockquote {
				line = stripBlockquotePrefix(line)
			}
			if strings.TrimSpace(line) == "" || isIndentedCodeLine(line) {
				cur.content = append(cur.content, fenceLine{no: no, text: dedentCodeLine(line)})
				continue
			}
			cur.closeLine = no - 1
			blocks = append(blocks, *cur)
			cur = nil
		}
		if cur == nil {
			line := stripBlockquotePrefix(raw)
			quoted := line != raw
			if c, n, lang, ok := openFence(line); ok {
				cur = &fenceBlock{openLine: no, language: lang, blockquote: quoted}
				fenceChar, fenceLen = c, n
			} else if isIndentedCodeLine(line) {
				cur = &fenceBlock{openLine: no, closeLine: no, indented: true, blockquote: quoted}
				cur.content = append(cur.content, fenceLine{no: no, text: dedentCodeLine(line)})
			}
			continue
		}
		line := raw
		if cur.blockquote {
			line = stripBlockquotePrefix(line)
		}
		if isCloseFence(line, fenceChar, fenceLen) {
			cur.closeLine = no
			blocks = append(blocks, *cur)
			cur = nil
			continue
		}
		cur.content = append(cur.content, fenceLine{no: no, text: line})
	}
	if cur != nil {
		cur.closeLine = len(lines)
		cur.unclosed = true
		blocks = append(blocks, *cur)
	}

	// Headings must be re-associated per block (nearest preceding heading),
	// so re-scan: walk lines again tracking heading at each block start.
	res := &ParseResult{}
	stepNo := 0
	for _, b := range blocks {
		res.Blocks++
		if !commandLangs[b.language] {
			res.SkippedBlocks++
			continue
		}
		h := headingAt(lines, b.openLine)
		for _, cmd := range logicalCommands(b) {
			stepNo++
			res.Steps = append(res.Steps, CandidateStep{
				ID:         fmt.Sprintf("readme-%d", stepNo),
				SourceFile: sourceFile,
				LineStart:  cmd.start,
				LineEnd:    cmd.end,
				FenceStart: b.openLine,
				FenceEnd:   b.closeLine,
				Language:   b.language,
				Heading:    h,
				Phase:      guessPhase(h),
				Command:    cmd.text,
				Unclosed:   b.unclosed,
			})
		}
	}
	return res, nil
}

type logicalCmd struct {
	start, end int
	text       string
}

// logicalCommands joins backslash continuations and drops blanks/comments.
func logicalCommands(b fenceBlock) []logicalCmd {
	out := []logicalCmd{}
	var buf []string
	start := 0
	flush := func(end int) {
		if len(buf) == 0 {
			return
		}
		out = append(out, logicalCmd{start: start, end: end, text: strings.Join(buf, " ")})
		buf = nil
	}
	for _, ln := range b.content {
		t := ln.text
		if sessionLangs[b.language] {
			t = strings.TrimPrefix(t, "$ ")
		}
		t = strings.TrimPrefix(t, "$ ")
		trimmed := strings.TrimSpace(t)
		if len(buf) == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue // blank or comment line outside a continuation
		}
		if len(buf) == 0 {
			if _, _, _, isFence := openFence(trimmed); isFence {
				continue // nested fence markup is structure, not a command
			}
		}
		if len(buf) == 0 {
			start = ln.no
		}
		if strings.HasSuffix(trimmed, "\\") && !strings.HasSuffix(trimmed, "\\\\") {
			buf = append(buf, strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")))
			continue
		}
		buf = append(buf, trimmed)
		flush(ln.no)
	}
	if len(buf) > 0 {
		flush(b.content[len(b.content)-1].no)
	}
	return out
}

// headingAt returns the nearest ATX heading above the given 1-based line.
func headingAt(lines []string, openLine int) string {
	for i := openLine - 2; i >= 0; i-- {
		line := stripBlockquotePrefix(lines[i])
		if h, ok := atxHeading(line); ok {
			return h
		}
		if i+1 < len(lines) && isSetextUnderline(stripBlockquotePrefix(lines[i+1])) {
			if h := strings.TrimSpace(line); h != "" && !isIndentedCodeLine(line) {
				return h
			}
		}
	}
	return ""
}

func isSetextUnderline(line string) bool {
	s := strings.TrimSpace(line)
	if len(s) < 3 || (s[0] != '=' && s[0] != '-') {
		return false
	}
	for _, r := range s {
		if r != rune(s[0]) {
			return false
		}
	}
	return true
}

func stripBlockquotePrefix(line string) string {
	s := line
	for depth := 0; depth < 8; depth++ {
		i := 0
		for i < len(s) && s[i] == ' ' && i < 3 {
			i++
		}
		if i >= len(s) || s[i] != '>' {
			break
		}
		s = s[i+1:]
		if strings.HasPrefix(s, " ") {
			s = s[1:]
		}
	}
	return s
}

func isIndentedCodeLine(line string) bool {
	if strings.HasPrefix(line, "\t") {
		return true
	}
	return len(line)-len(strings.TrimLeft(line, " ")) >= 4
}

func dedentCodeLine(line string) string {
	if strings.HasPrefix(line, "\t") {
		return line[1:]
	}
	if len(line) >= 4 && line[:4] == "    " {
		return line[4:]
	}
	return line
}

// atxHeading matches "# Heading" with up to 3 leading spaces.
func atxHeading(line string) (string, bool) {
	s := line
	i := 0
	for i < len(s) && s[i] == ' ' && i < 3 {
		i++
	}
	if i == 3 && len(s) > 3 && s[3] == ' ' {
		return "", false // 4+ spaces: indented, not a heading
	}
	j := i
	for j < len(s) && s[j] == '#' {
		j++
	}
	depth := j - i
	if depth == 0 || depth > 6 {
		return "", false
	}
	rest := s[j:]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return "", false // "#tag" is not a heading
	}
	h := strings.TrimSpace(rest)
	h = strings.TrimRight(h, "#")
	return strings.TrimSpace(h), true
}

// openFence matches a fence opening line: up to 3 spaces, 3+ backticks
// or tildes, optional info string. Backtick info may not contain backticks.
func openFence(line string) (char byte, length int, lang string, ok bool) {
	i := 0
	for i < len(line) && line[i] == ' ' && i < 3 {
		i++
	}
	if i < len(line) && line[i] == ' ' {
		return 0, 0, "", false
	}
	if i >= len(line) || (line[i] != '`' && line[i] != '~') {
		return 0, 0, "", false
	}
	c := line[i]
	j := i
	for j < len(line) && line[j] == c {
		j++
	}
	if j-i < 3 {
		return 0, 0, "", false
	}
	info := strings.TrimSpace(line[j:])
	if c == '`' && strings.Contains(info, "`") {
		return 0, 0, "", false
	}
	lang = ""
	if f := strings.Fields(strings.ToLower(info)); len(f) > 0 {
		lang = f[0]
	}
	return c, j - i, lang, true
}

// isCloseFence matches a closing fence: same char, run >= open length,
// nothing but whitespace after.
func isCloseFence(line string, char byte, openLen int) bool {
	i := 0
	for i < len(line) && line[i] == ' ' && i < 3 {
		i++
	}
	j := i
	for j < len(line) && line[j] == char {
		j++
	}
	if j-i < openLen || j-i < 3 {
		return false
	}
	return strings.TrimSpace(line[j:]) == ""
}

// guessPhase is a keyword heuristic over heading text, checked in
// verify > install > launch order. Always a guess, never a promise.
func guessPhase(heading string) string {
	h := strings.ToLower(heading)
	contains := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(h, w) {
				return true
			}
		}
		return false
	}
	if contains("test", "verify", "verificat", "check", "validat", "проверка") {
		return PhaseVerify
	}
	if contains("install", "setup", "prerequisit", "dependenc", "установка") {
		return PhaseInstall
	}
	if contains("run", "start", "launch", "usage", "quickstart", "quick start", "example", "запуск") {
		return PhaseLaunch
	}
	return PhaseUnknown
}
