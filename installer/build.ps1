$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$installer = $PSScriptRoot
$out = Join-Path $installer 'out'

# Single source of truth: package version from Cargo.toml.
$toml = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
    throw 'Cannot read package version from Cargo.toml.'
}
$version = $Matches[1]

Write-Host "==> Building ipscan $version (release)"
Push-Location $root
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw 'cargo build --release failed.' }
}
finally { Pop-Location }

New-Item -ItemType Directory -Force -Path $out | Out-Null

# Locate the Inno Setup compiler.
$iscc = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    $found = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($found) { $iscc = $found.Source }
}
if (-not $iscc) {
    throw 'ISCC.exe not found. Install Inno Setup 6 (winget install JRSoftware.InnoSetup).'
}

Write-Host '==> Building setup.exe (Inno Setup)'
Push-Location $installer
try {
    & $iscc (Join-Path $installer 'ipscan.iss') "/O$out" "/dAppVersion=$version" "/Fipscan-$version-setup"
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compile failed.' }
}
finally { Pop-Location }

Write-Host '==> Building .msi (WiX Toolset)'
Push-Location $installer
try {
    & wix build (Join-Path $installer 'ipscan.wxs') `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -d "Version=$version" `
        -pdbtype none `
        -o (Join-Path $out "ipscan-$version.msi")
    if ($LASTEXITCODE -ne 0) { throw 'WiX build failed.' }
}
finally { Pop-Location }

Write-Host "`n==> Installers:"
Get-ChildItem $out -Filter "ipscan-$version*" | Select-Object Name, Length
