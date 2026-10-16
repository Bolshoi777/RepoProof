# Build a portable RepoProof release (R1): vet, test, build CLI +
# desktop, checksum, zips. No NSIS installer on this machine (checked):
# desktop ships as a portable zip until an installer step exists.
# Usage: powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 [-Version 0.1.0]
# Development-only incremental snapshot: add -SkipValidation. This never
# satisfies the release gate and must not be used for public artifacts.
param(
  [string]$Version = "0.1.0",
  [switch]$SkipValidation
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $root
$out = Join-Path $root "dist"
New-Item -ItemType Directory -Force $out | Out-Null

if ($SkipValidation) {
  Write-Warning "development snapshot only: validation was skipped; do not use this mode for a public release"
} else {
  Write-Host "== vet =="
  go vet ./...
  if ($LASTEXITCODE -ne 0) { throw "go vet failed" }
  Write-Host "== full regression test =="
  go test ./... -count=1
  if ($LASTEXITCODE -ne 0) { throw "go test failed" }
  Write-Host "== module verification =="
  go mod verify
  if ($LASTEXITCODE -ne 0) { throw "go mod verify failed" }
}
Write-Host "== SBOM =="
$sbom = Join-Path $out "repoproof-$Version.spdx.json"
$packages = @()
go list -m -f "{{.Path}}|{{.Version}}" all | ForEach-Object {
  $parts = $_ -split "\|", 2
  if ($parts[0]) {
    $packages += [ordered]@{
      SPDXID = "SPDXRef-Package-" + (($parts[0] -replace '[^A-Za-z0-9.-]', '-') -replace '-+', '-')
      name = $parts[0]
      versionInfo = if ($parts.Count -gt 1) { $parts[1] } else { "" }
      downloadLocation = "NOASSERTION"
      licenseConcluded = "NOASSERTION"
      licenseDeclared = "NOASSERTION"
    }
  }
}
if ($LASTEXITCODE -ne 0 -or $packages.Count -eq 0) { throw "SBOM generation failed" }
[ordered]@{
  SPDXID = "SPDXRef-DOCUMENT"
  spdxVersion = "SPDX-2.3"
  dataLicense = "CC0-1.0"
  name = "RepoProof $Version"
  documentNamespace = "https://repoproof.dev/sbom/$Version"
  creationInfo = [ordered]@{ created = (Get-Date).ToUniversalTime().ToString("o"); creators = @("Tool: RepoProof build-release.ps1") }
  packages = $packages
} | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $sbom
Write-Host "== build =="
$exe = Join-Path $out "repoproof-$Version-windows-amd64.exe"
$ldflags = "-X github.com/repoproof/repoproof/internal/version.ModuleVersion=$Version"
# VCS stamping is optional metadata. Disable it so a checkout copied between
# Windows users (or marked as a Git safe-directory by another account) still
# produces a reproducible binary instead of failing before compilation.
go build -trimpath -buildvcs=false -ldflags $ldflags -o $exe ./cmd/repoproof
if ($LASTEXITCODE -ne 0) { throw "go build failed" }
Write-Host "== checksum =="
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$hash  repoproof-$Version-windows-amd64.exe" | Set-Content (Join-Path $out "repoproof-$Version-windows-amd64.exe.sha256")
Write-Host "== package =="
$zip = Join-Path $out "repoproof-$Version-windows-amd64.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $exe, (Join-Path $out "repoproof-$Version-windows-amd64.exe.sha256"), $sbom, (Join-Path $root "scripts\install-portable.ps1"), (Join-Path $root "LICENSE"), (Join-Path $root "CHANGELOG.md"), (Join-Path $root "docs\PRODUCT_README_EN.md"), (Join-Path (Join-Path $root "docs") "USER_GUIDE_EN.md") -DestinationPath $zip
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
Write-Host "OK: $zip"
Write-Host "exe sha256: $hash"
Write-Host "zip sha256: $zipHash"
Write-Host "== desktop =="
$wails = (Get-Command wails -ErrorAction SilentlyContinue).Source
if (-not $wails) {
  Write-Host "wails CLI not on PATH: desktop packaging skipped (CLI release above is complete)"
} else {
  $deskdir = Join-Path $root "desktop"
  Push-Location $deskdir
  # Keep developer checkout and module-cache paths out of the public binary.
  $oldGoFlags = $env:GOFLAGS
  if ([string]::IsNullOrWhiteSpace($oldGoFlags)) {
    $env:GOFLAGS = "-trimpath"
  } elseif ($oldGoFlags -notmatch '(^|\s)-trimpath(\s|$)') {
    $env:GOFLAGS = "$oldGoFlags -trimpath"
  }
  & $wails build
  if ($null -eq $oldGoFlags) { Remove-Item Env:GOFLAGS -ErrorAction SilentlyContinue } else { $env:GOFLAGS = $oldGoFlags }
  if ($LASTEXITCODE -ne 0) { throw "wails build failed" }
  Pop-Location
  $dexe = Join-Path $deskdir "build\bin\repoproof-desktop.exe"
  $dhash = (Get-FileHash $dexe -Algorithm SHA256).Hash.ToLower()
  "$dhash  repoproof-desktop-$Version-windows-amd64.exe" | Set-Content (Join-Path $out "repoproof-desktop-$Version-windows-amd64.exe.sha256")
  Copy-Item $dexe (Join-Path $out "repoproof-desktop-$Version-windows-amd64.exe")
  $dzip = Join-Path $out "repoproof-desktop-$Version-windows-amd64.zip"
  if (Test-Path $dzip) { Remove-Item $dzip }
  Compress-Archive -Path (Join-Path $out "repoproof-desktop-$Version-windows-amd64.exe"), (Join-Path $out "repoproof-desktop-$Version-windows-amd64.exe.sha256"), $sbom, (Join-Path $root "scripts\install-portable.ps1"), (Join-Path $root "LICENSE"), (Join-Path $root "CHANGELOG.md"), (Join-Path $root "docs\PRODUCT_README_EN.md"), (Join-Path (Join-Path $root "docs") "USER_GUIDE_EN.md") -DestinationPath $dzip
  $dzipHash = (Get-FileHash $dzip -Algorithm SHA256).Hash.ToLower()
  Remove-Item (Join-Path $out "repoproof-desktop-$Version-windows-amd64.exe")
  Write-Host "OK: $dzip"
  Write-Host "exe sha256: $dhash"
  Write-Host "zip sha256: $dzipHash"
}
