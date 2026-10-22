param(
    [Parameter(Mandatory = $true)][string]$Computer,
    [string]$Dest = "C:\suspex",
    [string]$User = ""
)

# Driver verification gate: run the full drv_exerciser matrix ON the target.
# Exit code 0 = every IOCTL exercised clean. The agent's gRPC surface may only
# be enabled after this passes.

$ErrorActionPreference = "Stop"
$exe = "$Dest\drv_exerciser.exe"

$cmds = @(
    "ping",
    "selftest",
    "procs",
    "mods",
    "mods --kernel",
    "kalloc --size 4096",
    "physwr-verify",
    # v8: watchdog smoke — arm+kick+list+disarm on id=0xDEAD, never fires.
    # `wdg-fire` is deliberately excluded: it BSODs the target.
    "wdg-smoke"
)

$failed = $false
foreach ($c in $cmds) {
    Write-Host "==> $c" -ForegroundColor Cyan
    $out = Invoke-Command -ComputerName $Computer -ScriptBlock {
        param($exe, $c)
        $p = Start-Process -FilePath $exe -ArgumentList $c -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput "$env:TEMP\suspex_ex_out.txt" -RedirectStandardError "$env:TEMP\suspex_ex_err.txt"
        Get-Content "$env:TEMP\suspex_ex_out.txt"
        Get-Content "$env:TEMP\suspex_ex_err.txt"
        $p.ExitCode
    } -ArgumentList $exe, $c
    $lines = @($out)
    $code = $lines[-1]
    $lines[0..($lines.Count - 2)] | ForEach-Object { Write-Host "    $_" }
    if ("$code" -ne "0") {
        Write-Host "    FAILED (exit $code)" -ForegroundColor Red
        $failed = $true
    }
}

Write-Host ""
if ($failed) {
    Write-Host "DRIVER GATE FAILED - do not enable the agent gRPC driver surface." -ForegroundColor Red
    exit 1
}
Write-Host "DRIVER GATE PASSED (core matrix; bp/rcall subcommands exercise target processes on demand)" -ForegroundColor Green
