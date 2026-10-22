param(
    [string]$AgentPath = ".\build\agent\Release\suspex_agent.exe",
    [string]$DriverPath = ".\build\driver\Release\suspex_driver.sys",
    [string]$MapperPath = ".\build\mapper\Release\mapper.exe",
    [string]$ExerciserPath = ".\build\tools\Release\drv_exerciser.exe",
    [int]$Port = 50074,
    [int]$UmagentPort = 50075,
    [string]$Token = $(throw "-Token is required (long random string)")
)

# Install the agent (and optional umagent) as demand-start Windows services.
# Run this ON THE TARGET VM from an elevated prompt, with the suspex0 payload
# directory as the working directory. Imports any *.cer sitting next to it
# into LocalMachine Root + TrustedPublishers so the test-signed driver loads.

$ErrorActionPreference = "Stop"
$dest = $PSScriptRoot

foreach ($pair in @(@("agent", $AgentPath), @("driver", $DriverPath), @("mapper", $MapperPath), @("exerciser", $ExerciserPath))) {
    $src = Resolve-Path $pair[1] -ErrorAction SilentlyContinue
    if ($src) {
        Copy-Item $src.Path $dest -Force
    }
}

$agent = Join-Path $dest "suspex_agent.exe"
if (-not (Test-Path $agent)) {
    throw "suspex_agent.exe not found in $dest; pass -AgentPath"
}

# trust the test-signing cert chain on THIS machine (required for the kernel
# to accept the driver; TESTSIGNING ON alone is not sufficient for a
# self-signed code-signing cert)
Get-ChildItem $dest -Filter "*.cer" | ForEach-Object {
    Write-Host "importing $($_.Name) into LocalMachine Root + TrustedPublisher"
    Import-Certificate -FilePath $_.FullName -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $_.FullName -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}

# testsigning must be ON for the driver; warn early
$ts = (bcdedit /enum '{current}' | Select-String "testsigning\s+Yes")
if (-not $ts) {
    Write-Warning "TESTSIGNING is OFF. Run: bcdedit /set TESTSIGNING ON  (then REBOOT) or the driver will not load."
}

function Install-Service($name, $binPath) {
    # idempotent: stop + delete any existing instance before creating
    sc.exe stop $name | Out-Null
    Start-Sleep -Milliseconds 500
    sc.exe delete $name | Out-Null
    Start-Sleep -Milliseconds 500
}

Install-Service "SuspexAgent"
sc.exe create SuspexAgent binPath= "`"$agent`" --port $Port --token `"$Token`"" type= own start= demand DisplayName= "Suspex0 Agent"
if ($LASTEXITCODE -ne 0) { throw "sc create failed" }

sc.exe description SuspexAgent "Suspex0 authorized-lab assessment agent (gRPC :$Port)"
if ($LASTEXITCODE -ne 0) { throw "sc description failed" }

# Auto-restart on unclean exit: bugs in the debug/engine path have crashed the
# agent process before, and without this the RPC endpoint stays dead until
# someone with local access runs `sc start SuspexAgent`. reset= keeps the
# fail counter honest so a real user-triggered stop isn't restarted.
sc.exe failure SuspexAgent reset= 300 actions= restart/5000/restart/5000/restart/15000 | Out-Null
sc.exe failureflag SuspexAgent 1 | Out-Null

netsh advfirewall firewall delete rule name="Suspex0 Agent" | Out-Null
netsh advfirewall firewall add rule name="Suspex0 Agent" dir=in action=allow protocol=TCP localport=$Port remoteip=127.0.0.1,192.168.0.0/16,10.0.0.0/8 | Out-Null

if ($UmagentPort -gt 0) {
    $umagent = Join-Path $dest "suspex_umagent.exe"
    if (Test-Path $umagent) {
        Install-Service "SuspexUmagent"
        # --bind 0.0.0.0: the umagent defaults to 127.0.0.1 (same-host parity
        # view); the orchestrator reaches it remotely, so bind all interfaces.
        # The token is the only gate — keep the VM off untrusted networks.
        sc.exe create SuspexUmagent binPath= "`"$umagent`" --port $UmagentPort --bind 0.0.0.0 --token `"$Token`"" type= own start= demand DisplayName= "Suspex0 Umagent"
        if ($LASTEXITCODE -ne 0) { throw "sc create (umagent) failed" }
        sc.exe description SuspexUmagent "Suspex0 usermode-only parity view (gRPC :$UmagentPort)"
        netsh advfirewall firewall delete rule name="Suspex0 Umagent" | Out-Null
        netsh advfirewall firewall add rule name="Suspex0 Umagent" dir=in action=allow protocol=TCP localport=$UmagentPort remoteip=127.0.0.1,192.168.0.0/16,10.0.0.0/8 | Out-Null
        Write-Host "Umagent installed: sc start SuspexUmagent"
    } else {
        Write-Warning "suspex_umagent.exe not found in $dest - umagent service skipped"
    }
}

Write-Host ""
Write-Host "Installed. Start with:  sc start SuspexAgent"
Write-Host "Driver load happens via MCP target_manage(action='driver_load') or:"
Write-Host "  sc create SuspexDrv type= kernel start= demand binPath= '\??\$dest\suspex_driver.sys'"
Write-Host "NOTE: driver binary updates need a reboot if the driver is currently loaded."
