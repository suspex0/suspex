param(
    [string]$SysPath = ".\build\driver\Release\suspex_driver.sys",
    [string]$CertName = "Suspex0 Test Signing",
    [switch]$CreateCertOnly
)

# Test-sign the driver with a self-signed certificate. The target VM accepts
# it with TESTSIGNING ON; the cert is installed there automatically when the
# driver service loads (via the machine ROOT store on the build host export).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sysPath = Join-Path $root $SysPath
if (-not (Test-Path $sysPath)) {
    # fall back to absolute path form
    if (-not (Test-Path $SysPath)) { throw "driver not found: $sysPath" }
    $sysPath = $SysPath
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -match "x64$" } |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found under Windows Kits\10\bin" }

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match $CertName } | Select-Object -First 1
if (-not $cert) {
    Write-Host "creating self-signed cert '$CertName'"
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
        -KeyUsage DigitalSignature -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) `
        -CertStoreLocation "Cert:\CurrentUser\My"
    Export-Certificate -Cert $cert -FilePath (Join-Path $env:TEMP "$CertName.cer") | Out-Null
    Import-Certificate -FilePath (Join-Path $env:TEMP "$CertName.cer") -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Write-Host "cert created and added to LocalMachine\Root (also import the .cer on the target VM: $env:TEMP\$CertName.cer)"
}
if ($CreateCertOnly) { exit 0 }

& $signtool sign /v /fd SHA256 /n $CertName /s My $sysPath
if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
Write-Host "signed: $sysPath"
Write-Host "NOTE: import the cert into the target VM LocalMachine\Root before loading, and keep TESTSIGNING ON."
