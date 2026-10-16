# Install a RepoProof portable package without admin rights.
# The package must contain exactly one executable and its .sha256 sidecar.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$PackagePath,
  [string]$InstallRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$package = (Resolve-Path -LiteralPath $PackagePath).Path
if (-not (Test-Path -LiteralPath $package -PathType Leaf) -or
    [IO.Path]::GetExtension($package) -ne ".zip") {
  throw "PackagePath must be an existing .zip file"
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ("repoproof-install-" + [guid]::NewGuid().ToString("N"))
$backup = $null
$installStage = $null
try {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  New-Item -ItemType Directory -Path $stage -Force | Out-Null
  $archive = [IO.Compression.ZipFile]::OpenRead($package)
  try {
    foreach ($entry in $archive.Entries) {
      $parts = $entry.FullName -replace "\\", "/" -split "/"
      if ([IO.Path]::IsPathRooted($entry.FullName) -or ($parts -contains "..") -or $entry.FullName.StartsWith("/")) {
        throw "Unsafe path in package: $($entry.FullName)"
      }
    }
  } finally {
    $archive.Dispose()
  }
  Expand-Archive -LiteralPath $package -DestinationPath $stage -Force

  $executables = @(Get-ChildItem -LiteralPath $stage -File -Filter "*.exe" -Recurse)
  if ($executables.Count -ne 1) {
    throw "Expected one executable, found $($executables.Count)"
  }
  $exe = $executables[0]
  if ($exe.Directory.FullName -ne (Get-Item -LiteralPath $stage).FullName) {
    throw "Executable must be at the package root"
  }
  if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $flavor = if ($exe.Name -like "*desktop*") { "Desktop" } else { "CLI" }
    $InstallRoot = Join-Path $env:LOCALAPPDATA ("Programs\RepoProof\" + $flavor)
  }
  $sidecar = Join-Path $stage ($exe.Name + ".sha256")
  if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf)) {
    throw "Missing checksum sidecar: $($exe.Name).sha256"
  }
  $line = (Get-Content -LiteralPath $sidecar -Raw).Trim()
  if ($line -notmatch "^(?<hash>[0-9a-fA-F]{64})\s+(?<name>\S+)\s*$" -or $Matches.name -ne $exe.Name) {
    throw "Invalid checksum sidecar"
  }
  $actual = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash
  if ($actual -ine $Matches.hash) {
    throw "Executable checksum mismatch"
  }

  $parent = Split-Path -Parent $InstallRoot
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $installStage = "$InstallRoot.new-$([guid]::NewGuid().ToString('N'))"
  Move-Item -LiteralPath $stage -Destination $installStage
  $stage = $null
  if (Test-Path -LiteralPath $InstallRoot) {
    $backup = "$InstallRoot.old-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
    Move-Item -LiteralPath $InstallRoot -Destination $backup
  }
  Move-Item -LiteralPath $installStage -Destination $InstallRoot
  $installStage = $null
  $installed = Join-Path $InstallRoot $exe.Name
  Write-Output "Installed $($exe.Name) to $InstallRoot"
  Write-Output "Run: $installed"
} finally {
  if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
  if ($installStage -and (Test-Path -LiteralPath $installStage)) { Remove-Item -LiteralPath $installStage -Recurse -Force -ErrorAction SilentlyContinue }
  if ($backup -and -not (Test-Path -LiteralPath $InstallRoot) -and (Test-Path -LiteralPath $backup)) {
    Move-Item -LiteralPath $backup -Destination $InstallRoot -ErrorAction SilentlyContinue
  }
  if ($backup) { Write-Warning "Previous installation retained at $backup" }
}
