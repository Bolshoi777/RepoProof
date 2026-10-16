[CmdletBinding()]
param([string]$EvidenceRoot = "docs\evidence")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$script:GateFailed = $false
function Fail-Gate([string]$Message) {
  Write-Output "NO-GO: $Message"
  exit 2
}
function Has-Property($Object, [string]$Name) {
  return $null -ne $Object.PSObject.Properties[$Name] -and
    -not [string]::IsNullOrWhiteSpace([string]$Object.$Name)
}
function Require-Status($Object, [string]$Name, [string]$Context) {
  if (-not (Has-Property $Object $Name) -or [string]$Object.$Name -ne "PASS") {
    Fail-Gate "$Context is not PASS"
  }
}
function Require-Sha256([string]$Value, [string]$Context) {
  if ($Value -notmatch '^[0-9a-fA-F]{64}$') {
    Fail-Gate "$Context has malformed SHA-256"
  }
}
function Reject-Placeholder([string]$Raw, [string]$Name) {
  if ($Raw -match 'EXAMPLE_NOT_VALID|REPLACE_WITH|NOT_RUN') {
    Fail-Gate "$Name contains placeholder or NOT_RUN data"
  }
}
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$base = Join-Path $root $EvidenceRoot
$required = @(
  "native-attestation.json",
  "security-lab-12.json",
  "clean-machine-windows.json",
  "external-e2e-matrix.csv",
  "license-scan.json",
  "authenticode.json",
  "provenance.json"
)
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $base $_) -PathType Leaf) })
if ($missing.Count -gt 0) {
  Write-Output "NO-GO: missing independent release evidence"
  $missing | ForEach-Object { Write-Output "  missing: $_" }
  exit 2
}

foreach ($name in @("native-attestation.json", "security-lab-12.json", "clean-machine-windows.json", "license-scan.json", "authenticode.json", "provenance.json")) {
  $path = Join-Path $base $name
  try {
    $raw = Get-Content -LiteralPath $path -Raw
    Reject-Placeholder $raw $name
    $obj = $raw | ConvertFrom-Json
  }
  catch { Fail-Gate "invalid JSON receipt $name" }
  if ($null -eq $obj) { Fail-Gate "empty receipt $name" }
  switch ($name) {
    "native-attestation.json" {
      Require-Status $obj "status" "native attestation"
      foreach ($field in @("worker_kind", "image_digest", "policy_digest", "attestation_authority", "signature_ref")) {
        if (-not (Has-Property $obj $field)) { Fail-Gate "native attestation missing $field" }
      }
      foreach ($field in @("image_digest", "policy_digest")) {
        if ([string]$obj.$field -notmatch '^sha256:[0-9a-fA-F]{64}$') { Fail-Gate "native attestation has malformed $field" }
      }
    }
    "security-lab-12.json" {
      Require-Status $obj "status" "security lab"
      if (-not (Has-Property $obj "authority")) { Fail-Gate "security lab missing authority" }
      $expectedScenarios = @("host-file-read", "host-file-write", "secret-access", "socket-access", "network-egress", "local-network", "resource-limits", "symlink-traversal", "log-xss", "log-secrets", "cancellation", "renderer-failure")
      if ($null -eq $obj.scenarios -or @($obj.scenarios).Count -ne $expectedScenarios.Count) { Fail-Gate "security lab must contain exactly 12 scenarios" }
      $actualScenarios = @($obj.scenarios | ForEach-Object { [string]$_.id })
      foreach ($scenario in $expectedScenarios) {
        if ($actualScenarios -notcontains $scenario) { Fail-Gate "security lab missing scenario $scenario" }
      }
      foreach ($scenario in @($obj.scenarios)) {
        if ([string]$scenario.status -ne "PASS") { Fail-Gate "security scenario $($scenario.id) is not PASS" }
      }
    }
    "clean-machine-windows.json" {
      foreach ($field in @("windows", "install", "hidpi", "abort_rerun", "report_parity")) {
        if (-not (Has-Property $obj $field)) { Fail-Gate "clean-machine receipt missing $field" }
      }
      foreach ($field in @("install", "hidpi", "abort_rerun", "report_parity")) {
        Require-Status $obj $field "clean-machine $field"
      }
    }
    "license-scan.json" {
      Require-Status $obj "status" "license scan"
      if ($null -eq $obj.packages -or @($obj.packages).Count -eq 0) { Fail-Gate "license scan has no packages" }
      foreach ($package in @($obj.packages)) {
        if (-not (Has-Property $package "name") -or -not (Has-Property $package "license")) { Fail-Gate "license scan package is incomplete" }
        if ([string]$package.license -match 'NOASSERTION|UNKNOWN|UNRESOLVED') { Fail-Gate "license scan contains unresolved license" }
      }
    }
    "authenticode.json" {
      Require-Status $obj "status" "Authenticode receipt"
      if (-not (Has-Property $obj "sha256")) { Fail-Gate "Authenticode receipt missing sha256" }
      Require-Sha256 ([string]$obj.sha256) "Authenticode receipt sha256"
    }
    "provenance.json" {
      foreach ($field in @("commit", "tag", "cli_sha256", "desktop_sha256")) {
        if (-not (Has-Property $obj $field)) { Fail-Gate "provenance receipt missing $field" }
      }
      if ([string]$obj.commit -notmatch '^[0-9a-fA-F]{40}$') { Fail-Gate "provenance commit is not a full SHA" }
      if ([string]$obj.tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+') { Fail-Gate "provenance tag is not a release tag" }
      Require-Sha256 ([string]$obj.cli_sha256) "provenance cli_sha256"
      Require-Sha256 ([string]$obj.desktop_sha256) "provenance desktop_sha256"
    }
  }
}

$matrixPath = Join-Path $base "external-e2e-matrix.csv"
$matrixRaw = Get-Content -LiteralPath $matrixPath -Raw
Reject-Placeholder $matrixRaw "external-e2e-matrix.csv"
$matrix = Import-Csv -LiteralPath $matrixPath
if (@($matrix).Count -lt 10) {
  Fail-Gate "external E2E matrix has fewer than 10 rows"
}
foreach ($field in @("id", "repository", "commit", "status", "evidence")) {
  if ($null -eq $matrix[0].PSObject.Properties[$field]) { Fail-Gate "external E2E matrix missing column $field" }
}
$seenIDs = @{}
$seenRepositories = @{}
foreach ($row in @($matrix)) {
  if ([string]::IsNullOrWhiteSpace([string]$row.id)) { Fail-Gate "external E2E row has no id" }
  if ($seenIDs.ContainsKey([string]$row.id)) { Fail-Gate "external E2E has duplicate id $($row.id)" }
  $seenIDs[[string]$row.id] = $true
  if ([string]$row.repository -notmatch '^https://github\.com/[^/]+/[^/]+/?$') { Fail-Gate "external E2E repository is not a public GitHub URL" }
  $repositoryKey = ([string]$row.repository).TrimEnd('/').ToLowerInvariant()
  if ($seenRepositories.ContainsKey($repositoryKey)) { Fail-Gate "external E2E has duplicate repository $($row.repository)" }
  $seenRepositories[$repositoryKey] = $true
  if ([string]$row.commit -notmatch '^[0-9a-fA-F]{40}$') { Fail-Gate "external E2E row $($row.id) is not pinned to a full commit" }
  if ([string]$row.status -notin @("VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "BLOCKED_SECURITY", "BLOCKED_ENVIRONMENT")) { Fail-Gate "external E2E row $($row.id) has invalid status" }
  if ([string]$row.evidence -match '^\s*$') { Fail-Gate "external E2E row $($row.id) has no evidence reference" }
}
Write-Output "GO-CANDIDATE: required receipt files exist and parse"
Write-Output "Independent security and release review is still required."
exit 0
