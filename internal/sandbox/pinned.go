package sandbox

// PinnedPython is the audited portable CPython distribution.
// Digest recorded from the audited first fetch over HTTPS (TOFU with
// tamper-evidence: any upstream change fails loudly, never silently).
// Single source of truth: tests and provisioning share this spec.
func PinnedPython() FetchSpec {
	return FetchSpec{
		Kind:       RuntimePython,
		URL:        "https://github.com/astral-sh/python-build-standalone/releases/download/20261003/cpython-3.13.16+20261003-x86_64-pc-windows-msvc-install_only.tar.gz",
		SHA256:     "5e100ee3d592ff500f4408a624f054d202e32d9dba8a12b2226bef81083fd778",
		MaxBytes:   120 << 20,
		ExeRelPath: "python/python.exe",
		Version:    "3.13.16",
	}
}

// PinnedNode is the audited portable Node distribution. The runtime is
// structurally incompatible with AppContainers (see SECURITY_TESTS);
// the spec stays for provisioning machinery tests, never for execution.
func PinnedNode() FetchSpec {
	return FetchSpec{
		Kind:       RuntimeNode,
		URL:        "https://nodejs.org/dist/v22.18.0/node-v22.18.0-win-x64.zip",
		SHA256:     "c95d8a7e1c99e669cc08c9f1176e068c1f50847c37908fcb8c35b62482366511",
		MaxBytes:   80 << 20,
		ExeRelPath: "node-v22.18.0-win-x64/node.exe",
		Version:    "22.18.0",
	}
}
