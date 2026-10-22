# suspex0 quick-status window - run on the target VM to see, at a glance,
# whether SuspexAgent / SuspexUmagent / SuspexDrv are up and whether their
# gRPC ports are actually accepting connections.
#
# Not a log. No RPC content. Just a "is it alive?" tile that refreshes every
# 2 seconds until you close the window.

param(
    [int]$IntervalSeconds = 2,
    [int]$AgentPort       = 50074,
    [int]$UmagentPort     = 50075
)

$ErrorActionPreference = 'SilentlyContinue'

function Get-SvcStatus([string]$name) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $s) { return '(not installed)' }
    return $s.Status.ToString()
}

function Get-PortInfo([int]$port) {
    # netstat -ano parsing beats Get-NetTCPConnection: no PS module dependency,
    # sees listeners owned by SYSTEM/other sessions even without elevation.
    $lines = netstat.exe -ano 2>$null | Select-String ("[:.]{0}\s" -f $port)
    $listenPid = $null
    $conns = 0
    $peers = New-Object System.Collections.Generic.HashSet[string]
    foreach ($line in $lines) {
        $parts = ($line.ToString().Trim() -split '\s+')
        if ($parts.Count -lt 5) { continue }
        $proto, $local, $foreign, $state, $procId = $parts
        if ($proto -notmatch '^TCP') { continue }
        $localPort = ($local -split '[:.]')[-1]
        if ($localPort -ne "$port") { continue }
        if ($state -eq 'LISTENING') {
            $listenPid = [int]$procId
        } elseif ($state -eq 'ESTABLISHED') {
            $conns++
            $addr = ($foreign -split '[:.]')[0..(($foreign -split '[:.]').Count - 2)] -join ':'
            [void]$peers.Add($addr)
        }
    }
    $procName = if ($listenPid) {
        (Get-Process -Id $listenPid -ErrorAction SilentlyContinue).ProcessName
    } else { $null }
    return [pscustomobject]@{
        Listening   = [bool]$listenPid
        Pid         = $listenPid
        Process     = $procName
        Connections = $conns
        Peers       = @($peers)
    }
}

function Write-Row([string]$svc, [string]$status, [int]$port, $info) {
    $svcColor = switch ($status) { 'Running' {'Green'} 'Stopped' {'Red'} default {'Yellow'} }
    Write-Host ('  {0,-16}' -f $svc) -NoNewline
    Write-Host (' [{0,-8}]' -f $status) -ForegroundColor $svcColor -NoNewline
    if ($port -eq 0) { Write-Host ''; return }
    if ($info.Listening) {
        Write-Host (' port {0} LISTEN' -f $port) -ForegroundColor Green -NoNewline
        $procTxt = if ($info.Process) { $info.Process } else { '?' }
        Write-Host (' pid={0} ({1}) conns={2}' -f $info.Pid, $procTxt, $info.Connections)
        if ($info.Peers.Count -gt 0) {
            Write-Host ('                     peers: ' + (($info.Peers | Select-Object -First 4) -join ', '))
        }
    } else {
        Write-Host (' port {0} NOT LISTENING' -f $port) -ForegroundColor Red
    }
}

$host.UI.RawUI.WindowTitle = 'suspex0 watch (Ctrl+C to quit)'

while ($true) {
    Clear-Host
    Write-Host ('suspex0 status  --  ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
    Write-Host ('  refresh every {0}s  --  press Ctrl+C to quit' -f $IntervalSeconds) -ForegroundColor DarkGray
    Write-Host ''

    $agentStatus   = Get-SvcStatus 'SuspexAgent'
    $umagentStatus = Get-SvcStatus 'SuspexUmagent'
    $drvStatus     = Get-SvcStatus 'SuspexDrv'
    $agentInfo     = Get-PortInfo $AgentPort
    $umagentInfo   = Get-PortInfo $UmagentPort

    Write-Row 'SuspexAgent'   $agentStatus   $AgentPort   $agentInfo
    Write-Row 'SuspexUmagent' $umagentStatus $UmagentPort $umagentInfo
    Write-Row 'SuspexDrv'     $drvStatus     0            $null

    Start-Sleep -Seconds $IntervalSeconds
}
