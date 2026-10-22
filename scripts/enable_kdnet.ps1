# enable_kdnet.ps1 - turn on kernel debugging over the network (kdnet)
# inside the lab target VM.
#
# RUN ELEVATED, ON THE TARGET VM (not the host). The guest connects out
# over UDP to the host that will run kd.exe, so -HostIP is the HOST's
# address as seen from the guest (VirtualBox NAT: 10.0.2.2).
#
#   .\enable_kdnet.ps1 -HostIP 10.0.2.2 -Port 50000
#   .\enable_kdnet.ps1 -HostIP 192.168.56.1 -Key w.x.y.z
#   .\enable_kdnet.ps1 -Off          # undo: /debug off + clear dbgsettings
#   .\enable_kdnet.ps1 -WhatIf       # show the bcdedit calls, change nothing
#
# /debug on only takes effect on the NEXT boot - this script never reboots
# for you. After the reboot, attach from the host:
#   kd -k net:port=50000,key=<key>
#
# See docs/KDNET.md for when kd is the right call and what it costs
# (stealth confounder; patchguard_state reports kd_disables_pg).

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$HostIP = '10.0.2.2',     # VirtualBox NAT host address
    [int]$Port = 50000,
    [string]$Key = '1.2.3.4',         # kdnet key: four dot-separated parts
    # PCI bus/dev/func of the NIC, e.g. '0.3.0' - only needed when
    # bcdedit can't pick the NIC itself (kdnetlist.exe on the host
    # shows candidates).
    [string]$BusParams = '',
    [switch]$Off
)

$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
# -WhatIf still previews without elevation; real runs need admin.
if (-not $admin -and -not $WhatIfPreference) {
    throw 'run enable_kdnet.ps1 elevated (bcdedit needs admin)'
}

if ($Off) {
    if ($PSCmdlet.ShouldProcess('boot entry {current}', 'bcdedit /debug off')) {
        & bcdedit /debug '{current}' off
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug off failed ($LASTEXITCODE)" }
        # dbgsettings survives /debug off; drop it so a later plain
        # '/debug on' doesn't resurrect a stale hostip/key.
        & bcdedit /deletevalue '{dbgsettings}' hostip 2>$null | Out-Null
        & bcdedit /deletevalue '{dbgsettings}' port 2>$null | Out-Null
        & bcdedit /deletevalue '{dbgsettings}' key 2>$null | Out-Null
        & bcdedit /deletevalue '{dbgsettings}' busparams 2>$null | Out-Null
        & bcdedit /deletevalue '{dbgsettings}' dhcp 2>$null | Out-Null
    }
    Write-Host 'kernel debugging OFF (takes effect on next boot).'
    exit 0
}

if (($Key -split '\.').Count -ne 4) {
    throw "-Key must be four dot-separated parts (e.g. 'w.x.y.z'), got '$Key'"
}

# /dbgsettings takes colon-style keyword:value pairs (not element=x).
$dbg = @('/dbgsettings', 'net', "hostip:$HostIP", "port:$Port", "key:$Key")
if ($BusParams) { $dbg += "busparams:$BusParams" }

if ($PSCmdlet.ShouldProcess('{dbgsettings}', "bcdedit $($dbg -join ' ')")) {
    & bcdedit @dbg
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings failed ($LASTEXITCODE)" }
}
if ($PSCmdlet.ShouldProcess('boot entry {current}', 'bcdedit /debug on')) {
    & bcdedit /debug '{current}' on
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug on failed ($LASTEXITCODE)" }
}

Write-Host ''
Write-Host "kdnet armed: hostip=$HostIP port=$Port"
Write-Host 'WARNING: /debug on takes effect on the NEXT BOOT - reboot the'
Write-Host 'target (hvlab_ctl.ps1 reset / restore) before attaching.'
Write-Host ''
Write-Host 'Attach from the host once the VM is back up:'
Write-Host "  kd -k net:port=$Port,key=$Key"
Write-Host "  windbg -k net:port=$Port,key=$Key"
Write-Host ''
Write-Host 'Verify from the orchestrator: target_manage status reports'
Write-Host "kernel_debugger / patchguard_state='kd_disables_pg' when a kd is"
Write-Host 'attached. Undo with: scripts\enable_kdnet.ps1 -Off'
