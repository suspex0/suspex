# Start the suspex0 orchestrator (MCP :8765, dashboard) unless it is already
# running. Registered as the "Suspex0 Orchestrator" logon task; safe to run
# manually at any time.
#
# Log split (avoids the file-lock clash):
#   orchestrator-start.log  - this script's own lines (guarded writes)
#   orchestrator-boot.log   - orchestrator stdout (owned by the server)
#   orchestrator-boot.err   - orchestrator stderr
param([string]$Config = "configs\local.yaml")

$repo = Split-Path -Parent $PSScriptRoot
$orch = Join-Path $repo "orchestrator"
$exe = Join-Path $orch ".venv\Scripts\suspex-server.exe"
$py = Join-Path $orch ".venv\Scripts\python.exe"
$startLog = Join-Path $orch "orchestrator-start.log"
$bootLog = Join-Path $orch "orchestrator-boot.log"
$bootErr = Join-Path $orch "orchestrator-boot.err"

function Log([string]$msg) {
    try { "$(Get-Date -Format o) [start] $msg" | Out-File -FilePath $startLog -Append -Encoding utf8 -ErrorAction Stop } catch { }
}

$ErrorActionPreference = "Stop"
if (Test-Path $exe) {
    $launchExe = $exe
    $launchArgs = "--config `"$(Join-Path $repo $Config)`""
}
elseif (Test-Path $py) {
    $launchExe = $py
    $launchArgs = "-m suspex.server --config `"$(Join-Path $repo $Config)`""
}
else {
    Log "ERROR: neither suspex-server.exe nor venv python found under $orch"
    exit 1
}

$existing = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Log "already listening on :8765 (pid $($existing.OwningProcess)) - nothing to do"
    exit 0
}

Log "starting orchestrator: $(Split-Path -Leaf $launchExe) $launchArgs"
try {
    Start-Process -FilePath $launchExe -ArgumentList $launchArgs `
        -WorkingDirectory $orch -WindowStyle Hidden `
        -RedirectStandardOutput $bootLog -RedirectStandardError $bootErr
}
catch {
    Log "ERROR: Start-Process failed: $($_.Exception.Message)"
    exit 1
}

$up = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    if (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) { $up = $true; break }
}
if ($up) { Log "orchestrator is up on :8765" }
else { Log "WARNING: port 8765 not listening after 10s - check orchestrator-boot.err" }
