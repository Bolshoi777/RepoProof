// RepoProof desktop frontend: thin view over Go bindings. No logic
// here beyond rendering; verdicts come from the Core.
const $ = (id) => document.getElementById(id);
const state = { approvalPath: "", runID: "", timer: null, inspectTimer: null, done: false, events: [], busy: false, executionSupported: false };

function elapsedLabel(started) {
  const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
  const minutes = String(Math.floor(seconds / 60)).padStart(2, "0");
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

function eventPhase(message) {
  const s = String(message).toLowerCase();
  if (/(install|provision|setup|dependency|провиз|установ)/.test(s)) return "setup";
  if (/(launch|start|spawn|запуск)/.test(s)) return "launch";
  if (/(behavior|oracle|verify|assert|повед|провер)/.test(s)) return "behavior";
  return "system";
}

function renderProgress() {
  const filter = $("progress-filter").value;
  const visible = state.events.filter((e) => filter === "all" || e.phase === filter);
  $("progress").textContent = visible.map((e) => `[${e.phase}] ${e.message}`).join("\n");
  $("progress-count").textContent = `${state.events.length} event${state.events.length === 1 ? "" : "s"}`;
}

function invalidateApproval(message) {
  if (!state.approvalPath) return;
  state.approvalPath = "";
  if (message) {
    $("approve-out").textContent = message;
    $("result").textContent = "Draft a new approval for the current target and contract.";
  }
}

function setBusy(busy) {
  state.busy = busy;
  ["btn-inspect", "btn-approve", "btn-verify", "btn-check"].forEach((id) => {
    $(id).disabled = busy;
  });
  $("btn-verify").disabled = busy || !state.executionSupported;
  $("btn-check").disabled = busy || !state.executionSupported;
  $("btn-cancel").disabled = !busy;
}

function setExecutionSupport(supported, reason) {
  state.executionSupported = Boolean(supported);
  const hint = state.executionSupported
    ? ""
    : (reason || "Execution is disabled until an attested isolated worker is available.");
  ["btn-verify", "btn-check"].forEach((id) => { $(id).title = hint; });
  setBusy(state.busy);
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
}

function errorText(error) {
  if (error && typeof error === "object") {
    if (error.message) return String(error.message);
    if (error.error) return String(error.error);
    try { return JSON.stringify(error); } catch (_) { return "unknown backend error"; }
  }
  return String(error || "unknown backend error");
}

function inspectErrorHint(message) {
  const lower = message.toLowerCase();
  if (lower.includes("only https") || lower.includes("github.com") || lower.includes("query and fragment")) {
    return "Use a public URL such as https://github.com/owner/repository without /tree/main, /issues, or query parameters.";
  }
  if (lower.includes("git ") || lower.includes("connect") || lower.includes("network") || lower.includes("resolve")) {
    return "Check that Git is installed and this machine can reach github.com over HTTPS.";
  }
  return "Inspect is read-only; no repository code was executed.";
}

async function refreshBadge() {
  try {
    const raw = await window.go.main.App.SupportStatus();
    const s = JSON.parse(raw);
    const b = $("sandbox-badge");
    const detail = $("sandbox-detail");
    b.textContent = s.supported ? "sandbox: ready" : "sandbox: unavailable";
    b.className = "badge " + (s.supported ? "ok" : "bad");
    detail.textContent = s.supported
      ? "Native worker available for the approved run."
      : (s.reason || "Execution is fail-closed; inspection and planning remain available.");
    b.title = s.reason || detail.textContent;
    setExecutionSupport(s.supported, s.reason || detail.textContent);
  } catch (e) {
    const b = $("sandbox-badge");
    const detail = $("sandbox-detail");
    b.textContent = "sandbox: unknown";
    b.className = "badge unknown";
    detail.textContent = "Support probe failed; execution stays fail-closed.";
    setExecutionSupport(false, detail.textContent);
  }
}

async function doInspect() {
  if (state.runID && !state.done) return;
  const path = $("path").value.trim();
  if (!path) return;
  $("btn-inspect").disabled = true;
  $("btn-cancel-inspect").disabled = false;
  const started = Date.now();
  const updateInspectStatus = () => {
    $("inspect-out").textContent =
      `Inspecting… ${elapsedLabel(started)}\n` +
      "Resolving the repository and creating one pinned read-only snapshot.\n" +
      "GitHub URLs can take a few minutes on the first run; no repository code is executed.";
  };
  updateInspectStatus();
  state.inspectTimer = setInterval(updateInspectStatus, 1000);
  try {
    const raw = await window.go.main.App.InspectAndPlan(path);
    const payload = JSON.parse(raw);
    const rep = payload.inspect;
    const plan = payload.plan;
    $("inspect-out").textContent =
      `source: ${rep.source}\ncommit: ${rep.commit || "(none)"}\n` +
      `fingerprint: ${rep.source_fingerprint}\nstack: ${rep.stack} (${rep.support})\n` +
      `readme: ${rep.readme || "(none)"}  files: ${rep.file_count}  commands: ${(rep.readme_steps || []).length}`;
    const rows = (rep.readme_steps || []).map((s) =>
      `<tr><td>${esc(s.id)}</td><td>${esc(s.phase)}</td><td>L${s.line_start}-L${s.line_end}</td><td><code>${esc(s.command)}</code></td></tr>`
    ).join("");
    $("steps").innerHTML = `<tr><th>id</th><th>phase</th><th>lines</th><th>command</th></tr>` + (rows || `<tr><td colspan="4">(none)</td></tr>`);
    $("review").innerHTML = plan.needs_review
      ? `<b>NEEDS REVIEW</b><ul>${plan.review_reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
      : `<b>Plan is complete and unambiguous.</b> Execution still requires explicit approval below.`;
  } catch (e) {
    const message = errorText(e);
    $("inspect-out").textContent = `inspect failed: ${message}\n${inspectErrorHint(message)}`;
  } finally {
    clearInterval(state.inspectTimer);
    state.inspectTimer = null;
    $("btn-inspect").disabled = false;
    $("btn-cancel-inspect").disabled = true;
  }
}

async function doCancelInspect() {
  try {
    await window.go.main.App.CancelInspect();
    $("inspect-out").textContent += "\nCancelling…";
  } catch (e) {
    // The operation may have completed between the button click and cancel.
  }
}

async function doApprove() {
  if (state.runID && !state.done) return;
  const path = $("path").value.trim();
  const contract = $("contract").value.trim();
  const statement = $("statement").value.trim();
  if (!path || !contract || !statement) { $("approve-out").textContent = "path, contract and statement are required."; return; }
  $("btn-approve").disabled = true;
  try {
    const raw = await window.go.main.App.DraftApproval(path, contract, statement, $("ackall").checked);
    const d = JSON.parse(raw);
    state.approvalPath = d.path;
    $("approve-out").textContent = d.summary + "\napproval file: " + d.path;
  } catch (e) {
    $("approve-out").textContent = "approve failed: " + e;
  } finally {
    $("btn-approve").disabled = false;
  }
}

async function pollResult() {
  try {
    const raw = await window.go.main.App.VerifyResult(state.runID);
    const r = JSON.parse(raw);
    if (r.done) {
      clearInterval(state.timer);
      state.done = true;
      setBusy(false);
      $("btn-cancel").disabled = true;
      $("result").textContent = r.summary + `\nexit: ${r.exit}`;
      $("btn-save").disabled = !r.proof;
      $("btn-save-html").disabled = !r.proof;
    }
  } catch (e) {
    // A crashed/expired backend run must never leave the UI permanently busy.
    clearInterval(state.timer);
    state.done = true;
    setBusy(false);
    $("result").textContent = "run result unavailable; the backend run may have ended during cleanup";
  }
}

async function doVerify() {
  if (state.runID && !state.done) return;
  if (!state.executionSupported) { $("result").textContent = "Verification is disabled: no attested isolated worker is available."; return; }
  if (!state.approvalPath) { $("result").textContent = "Draft an approval first (section 2)."; return; }
  const path = $("path").value.trim();
  const contract = $("contract").value.trim();
  setBusy(true);
  try {
    state.runID = await window.go.main.App.StartVerify(path, contract, state.approvalPath);
    state.done = false;
    state.events = [];
    renderProgress();
    $("result").textContent = "";
    $("btn-cancel").disabled = false;
    $("btn-save").disabled = true;
    state.timer = setInterval(pollResult, 500);
  } catch (e) {
    $("result").textContent = "verify failed to start: " + e;
    setBusy(false);
  }
}

async function doCheck() {
  if (state.runID && !state.done) return;
  if (!state.executionSupported) { $("result").textContent = "Auto-check is disabled: no attested isolated worker is available."; return; }
  if (!$("confirm-check").checked) { $("result").textContent = "Tick the confirmation box first: the plan above is what will run."; return; }
  const path = $("path").value.trim();
  if (!path) { $("result").textContent = "Set the project path first (section 1)."; return; }
  setBusy(true);
  try {
    state.runID = await window.go.main.App.StartCheck(path, true);
    state.done = false;
    state.events = [];
    renderProgress();
    $("result").textContent = "";
    $("btn-cancel").disabled = false;
    $("btn-save").disabled = true;
    state.timer = setInterval(pollResult, 500);
  } catch (e) {
    $("result").textContent = "check failed to start: " + e;
    setBusy(false);
  }
}

async function doCancel() {
  if (!state.runID) return;
  try { await window.go.main.App.CancelVerify(state.runID); } catch (e) { /* already done */ }
}

async function doSave() {
  if (!state.runID) return;
  try {
    const p = await window.go.main.App.SaveProof(state.runID);
    $("result").textContent += "\nsaved: " + p;
  } catch (e) { $("result").textContent += "\nsave failed: " + e; }
}

async function doSaveHTML() {
  if (!state.runID) return;
  try {
    const p = await window.go.main.App.SaveProofHTML(state.runID);
    $("result").textContent += "\nsaved HTML: " + p;
  } catch (e) { $("result").textContent += "\nsave HTML failed: " + e; }
}

window.runtime.EventsOn("verify:progress", (ev) => {
  if (ev.run === state.runID) {
    const message = String(ev.msg || "");
    state.events.push({ phase: eventPhase(message), message });
    renderProgress();
  }
});
window.runtime.EventsOn("verify:done", (ev) => {
  if (ev.run === state.runID) pollResult();
});

$("btn-inspect").onclick = doInspect;
$("btn-cancel-inspect").onclick = doCancelInspect;
$("btn-browse").onclick = async () => {
  try {
    const p = await window.go.main.App.BrowseFolder();
    if (p) {
      invalidateApproval("Project target changed; draft approval again.");
      $("path").value = p;
    }
  } catch (e) {}
};
$("btn-browse-contract").onclick = async () => {
  try {
    const p = await window.go.main.App.BrowseFile();
    if (p) {
      invalidateApproval("Contract changed; draft approval again.");
      $("contract").value = p;
    }
  } catch (e) {}
};
$("btn-approve").onclick = doApprove;
$("btn-verify").onclick = doVerify;
$("btn-check").onclick = doCheck;
$("btn-cancel").onclick = doCancel;
$("btn-save").onclick = doSave;
$("btn-save-html").onclick = doSaveHTML;
$("progress-filter").onchange = renderProgress;
$("path").addEventListener("change", () => invalidateApproval("Project target changed; draft approval again."));
$("contract").addEventListener("change", () => invalidateApproval("Contract changed; draft approval again."));
setBusy(false);
refreshBadge();
