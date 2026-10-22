param(
    [Parameter(Mandatory = $true)][string]$Computer,
    [string]$Dest = "C:\suspex",
    [string]$Port = "50074",
    [string]$UmagentPort = "50075",
    [string]$Token = "",
    [switch]$EnableTestSigning,
    [switch]$NoReboot
)

# Deploy the suspex0 payload to a Windows lab VM: export + import the driver
# test-signing cert, enable testsigning (optional), copy agent/driver/mapper/
# exerciser/umagent, install the agent + umagent services.
# Snapshot the VM first — the driver has no guaranteed unload path; binary
# updates may require a reboot.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build"

$files = @(
    "$build\agent\Release\suspex_agent.exe",
    "$build\umagent\Release\suspex_umagent.exe",
    "$build\mapper\Release\mapper.exe",
    "$build\tools\Release\drv_exerciser.exe",
    "$build\driver\Release\suspex_driver.sys"
)
foreach ($f in $files) {
    if (-not (Test-Path $f)) {
        throw "missing build artifact: $f (run scripts\build.ps1 first)"
    }
}

# export the driver test-signing cert: the target VM must trust it or the
# kernel will refuse the driver even with TESTSIGNING ON
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -match "Suspex0 Test Signing" } | Select-Object -First 1
if (-not $cert) {
    throw "signing cert 'Suspex0 Test Signing' not found in CurrentUser\My (run scripts\sign_driver.ps1 first)"
}
$certFile = Join-Path $env:TEMP "Suspex0TestSigning.cer"
Export-Certificate -Cert $cert -FilePath $certFile -Type CERT | Out-Null

if (-not $Token) {
    $Token = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ })
    Write-Host "generated token: $Token"
}

$session = $null
$useSsh = $false
try {
    $session = New-PSSession -ComputerName $Computer -ErrorAction Stop
} catch {
    $useSsh = $true
    Write-Host "WinRM unavailable, falling back to ssh/scp for $Computer"
}

if ($useSsh) {
    ssh $Computer "if not exist $Dest mkdir $Dest"
    foreach ($f in $files) {
        scp $f "${Computer}:${Dest}/"
    }
    scp $certFile "${Computer}:${Dest}/Suspex0TestSigning.cer"
    scp (Join-Path $PSScriptRoot "install_agent_service.ps1") "${Computer}:${Dest}/"
    ssh $Computer "powershell -ExecutionPolicy Bypass -File $Dest\install_agent_service.ps1 -Port $Port -UmagentPort $UmagentPort -Token $Token"
} else {
    Invoke-Command -Session $session -ScriptBlock {
        param($dest)
        if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest | Out-Null }
    } -ArgumentList $Dest

    foreach ($f in $files) {
        Copy-Item -ToSession $session -Path $f -Destination $Dest -Force
    }
    Copy-Item -ToSession $session -Path $certFile -Destination "$Dest\Suspex0TestSigning.cer" -Force
    Copy-Item -ToSession $session -Path (Join-Path $PSScriptRoot "install_agent_service.ps1") -Destination $Dest -Force

    if ($EnableTestSigning) {
        Invoke-Command -Session $session -ScriptBlock {
            $ts = bcdedit /enum '{current}' | Select-String "testsigning\s+Yes"
            if (-not $ts) {
                bcdedit /set TESTSIGNING ON | Out-Null
                Write-Host "TESTSIGNING ON - reboot required"
                $script:needsReboot = $true
            }
        }
    }

    Invoke-Command -Session $session -ScriptBlock {
        param($dest, $port, $umport, $token)
        Set-Location $dest
        powershell -ExecutionPolicy Bypass -File "$dest\install_agent_service.ps1" -Port $port -UmagentPort $umport -Token $token
    } -ArgumentList $Dest, $Port, $UmagentPort, $Token
}

Write-Host ""
Write-Host "Deployed to ${Computer}${Dest}."
Write-Host "Next:"
Write-Host "  1. reboot the VM if testsigning was just enabled"
Write-Host "  2. start the services:"
Write-Host "       sc \\$Computer start SuspexAgent    (gRPC :$Port)"
Write-Host "       sc \\$Computer start SuspexUmagent  (gRPC :$UmagentPort)"
Write-Host "  3. gate the driver:  .\scripts\verify_roundtrip.ps1 -Computer $Computer"
Write-Host "     (NEVER wire gRPC to an unexercised IOCTL surface)"
Write-Host "  4. point configs/local.yaml at ${Computer}:${Port}/${UmagentPort} with the token, run suspex-server"
