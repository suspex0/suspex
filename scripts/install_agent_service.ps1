param(
    [string]$AgentPath = ".\build\agent\Release\suspex_agent.exe",
    [string]$DriverPath = ".\build\driver\Release\suspex_driver.sys",
    [string]$MapperPath = ".\build\mapper\Release\mapper.exe",
    [string]$ExerciserPath = ".\build\tools\Release\drv_exerciser.exe",
    [int]$Port = 50074,
    [int]$UmagentPort = 50075,
    [string]$Token = $(throw "-Token is required (long random string)"),
    # v0.31 Phase 5: boot autostart. 'auto' (default) starts the services at
    # boot; 'demand' preserves the old manual-start behavior.
    [ValidateSet("auto", "demand")]
    [string]$StartMode = "auto",
    # Rotating diagnostic log (agent + gRPC internals; session-0 post-mortem).
    # Empty string disables.
    [string]$LogPath = "",
    # Firewall remote scope for the agent ports. Default keeps the lab subnets;
    # pass "any" to allow all sources (token is the only gate then).
    [string]$RemoteIp = "127.0.0.1,192.168.0.0/16,10.0.0.0/8"
)

# Install the agent (and optional umagent) as Windows services with boot
# autostart, SCM crash recovery, rotating logs and firewall rules for every
# profile. Run this ON THE TARGET VM from an elevated prompt, with the
# suspex0 payload directory as the working directory. Imports any *.cer
# sitting next to it into LocalMachine Root + TrustedPublishers so the
# test-signed driver loads.
#
# NOTE: the exe IS a proper Windows service binary (SCM handshake in
# service_main.cpp). Never wrap it in `cmd /c ...` — the wrapper, not the
# exe, is what failed the SCM handshake with 1053 on the rig, and cmd pipes
# for stdio are the known "process up, port dead" wedge. Point binPath at
# the exe itself; put flags (--port/--token/--log/...) after it.

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

if (-not $LogPath) {
    $LogPath = Join-Path $dest "suspex_agent.log"
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

function Remove-ServiceIfExists($name) {
    # idempotent: stop + WAIT FOR FULL STOP + delete any existing instance
    # before creating. The wait matters: the v0.31 agent stops gracefully
    # (server shutdown + breadcrumb flush can take seconds), and deleting
    # a still-stopping service marks it for deletion — the subsequent
    # create then fails with ERROR_SERVICE_MARKED_FOR_DELETE and the old
    # service vanishes on next reboot. Never run this installer through
    # the agent's own exec API while it recreates the agent service: the
    # stopping agent reaps the child. Run it from a rig console (or via
    # exec run_detached, whose children survive agent restarts).
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    sc.exe stop $name | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $s -or $s.Status -eq "Stopped") { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Milliseconds 500
    sc.exe delete $name | Out-Null
    Start-Sleep -Milliseconds 500
}

function Set-ServiceRecovery($name) {
    # Auto-restart on unclean exit: bugs in the debug/engine path have
    # crashed the agent process before, and without this the RPC endpoint
    # stays dead until someone with local access intervenes. reset= keeps
    # the fail counter honest so a real user-triggered stop isn't
    # restarted.
    sc.exe failure $name reset= 300 actions= restart/5000/restart/5000/restart/15000 | Out-Null
    sc.exe failureflag $name 1 | Out-Null
}

Remove-ServiceIfExists "SuspexAgent"

# One canonical autostart: the SCM service above. Remove the legacy
# scheduled-task workarounds (onstart `cmd /c --dev` launcher + the 5-min
# netstat watchdog that re-ran it) — they raced the service at boot and
# left orphaned instances holding the port. The watchdog's job (revive a
# dead endpoint) is covered by sc failure recovery + the agent's built-in
# listener self-test/rebind.
foreach ($legacy in @("suspex-agent", "suspex-agent-watch")) {
    schtasks /change /tn $legacy /disable 2>$null | Out-Null
    schtasks /delete /tn $legacy /f 2>$null | Out-Null
    if ($?) { Write-Host "removed legacy task: $legacy" }
}

sc.exe create SuspexAgent binPath= "`"$agent`" --port $Port --token `"$Token`" --log `"$LogPath`"" type= own start= $StartMode DisplayName= "Suspex0 Agent"
if ($LASTEXITCODE -ne 0) {
    # retry once: a marked-for-delete remnant can reject the first create
    sc.exe delete SuspexAgent | Out-Null
    Start-Sleep -Seconds 1
    sc.exe create SuspexAgent binPath= "`"$agent`" --port $Port --token `"$Token`" --log `"$LogPath`"" type= own start= $StartMode DisplayName= "Suspex0 Agent"
}
if ($LASTEXITCODE -ne 0) { throw "sc create failed" }

sc.exe description SuspexAgent "Suspex0 authorized-lab assessment agent (gRPC :$Port)"
if ($LASTEXITCODE -ne 0) { throw "sc description failed" }

Set-ServiceRecovery "SuspexAgent"

# profile=any: the rig lost LAN reachability after NIC flaps moved the
# interface between firewall profiles — a profile-scoped rule went silent
# until an any-profile rule replaced it.
netsh advfirewall firewall delete rule name="Suspex0 Agent" | Out-Null
netsh advfirewall firewall add rule name="Suspex0 Agent" dir=in action=allow protocol=TCP localport=$Port profile=any remoteip=$RemoteIp | Out-Null

if ($UmagentPort -gt 0) {
    $umagent = Join-Path $dest "suspex_umagent.exe"
    if (Test-Path $umagent) {
        Remove-ServiceIfExists "SuspexUmagent"
        $uLog = Join-Path $dest "suspex_umagent.log"
        # --bind 0.0.0.0: the umagent defaults to 127.0.0.1 (same-host parity
        # view); the orchestrator reaches it remotely, so bind all interfaces.
        # The token is the only gate — keep the VM off untrusted networks.
        sc.exe create SuspexUmagent binPath= "`"$umagent`" --port $UmagentPort --bind 0.0.0.0 --token `"$Token`" --log `"$uLog`"" type= own start= $StartMode DisplayName= "Suspex0 Umagent"
        if ($LASTEXITCODE -ne 0) {
            sc.exe delete SuspexUmagent | Out-Null
            Start-Sleep -Seconds 1
            sc.exe create SuspexUmagent binPath= "`"$umagent`" --port $UmagentPort --bind 0.0.0.0 --token `"$Token`" --log `"$uLog`"" type= own start= $StartMode DisplayName= "Suspex0 Umagent"
        }
        if ($LASTEXITCODE -ne 0) { throw "sc create (umagent) failed" }
        sc.exe description SuspexUmagent "Suspex0 usermode-only parity view (gRPC :$UmagentPort)"
        Set-ServiceRecovery "SuspexUmagent"
        netsh advfirewall firewall delete rule name="Suspex0 Umagent" | Out-Null
        netsh advfirewall firewall add rule name="Suspex0 Umagent" dir=in action=allow protocol=TCP localport=$UmagentPort profile=any remoteip=$RemoteIp | Out-Null
        Write-Host "Umagent installed: sc start SuspexUmagent"
    } else {
        Write-Warning "suspex_umagent.exe not found in $dest - umagent service skipped"
    }
}

Write-Host ""
Write-Host "Installed ($StartMode start, SCM recovery, log: $LogPath)."
if ($StartMode -eq "demand") {
    Write-Host "Start now with:   sc start SuspexAgent"
} else {
    Write-Host "Starting now:     sc start SuspexAgent"
    sc.exe start SuspexAgent | Out-Null
}
Write-Host "Verify listener:  Test-NetConnection 127.0.0.1 -Port $Port"
Write-Host "Recovery policy:  sc qfailure SuspexAgent"
Write-Host "Driver load happens via MCP target_manage(action='driver_load') or:"
Write-Host "  sc create SuspexDrv type= kernel start= demand binPath= '\??\$dest\suspex_driver.sys'"
Write-Host "NOTE: driver binary updates need a reboot if the driver is currently loaded."
