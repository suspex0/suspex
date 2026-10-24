# Agent deployment & recovery runbook

How `suspex_agent.exe` / `suspex_umagent.exe` are provisioned on a rig, and
how they self-heal. Written after the rig field report (v1.0.1 Phase 5):
agent wedged after NIC churn (process alive, port LISTENING, all SYNs
timing out) and no reliable boot autostart.

## TL;DR

1. Install as **Windows services** — the exe IS a service binary (SCM
   handshake lives in `agent/src/service/service_main.cpp`). Do **not**
   wrap it in `cmd /c` and do not use `--dev` under a scheduled task.
2. Use `scripts/install_agent_service.ps1` — it wires boot autostart, SCM
   crash recovery, rotating logs, and `profile=any` firewall rules.
3. The agent self-heals: bind retries with backoff, a loopback listener
   self-test that tears down and rebuilds a wedged accept path, and a
   static-IPv4 pin option for NIC/DHCP churn.

## Why the old setup broke

Two independent failure modes were reported:

- **A. Wedged listener after network churn.** The agent ran as
  `cmd /c suspex_agent.exe --dev ...` under a scheduled task. In session 0,
  `cmd /c` hands the child **pipes for stdout/stderr that nobody drains**.
  gRPC logs connection errors to stderr while NICs flap; the pipe fills;
  whichever thread is inside that blocked write stalls — including the
  event-engine threads that drain accepts. The listening socket stays
  open (kernel backlog), new SYNs time out, `taskkill` + restart is the
  only recovery. v1.0.1 fixes: stderr is spliced onto a drain pipe and
  relayed into the rotating log file, service/task context redirects the
  remaining stdio to `NUL`, and a loopback self-test (`listen_watch.cpp`)
  rebuilds the listener if it ever wedges anyway.
- **B. No boot autostart.** The services were installed `start= demand`
  (or launched by an ad-hoc task/Run entry). v1.0.1 installs them
  `start= auto` with `sc failure ... actions= restart/...` so SCM owns
  both boot start and crash restarts.

## Provision (service mode — recommended)

On the target, elevated, payload dir as CWD:

```powershell
# copy agent/umagent/mapper/driver next to the script, import certs,
# create SuspexAgent + SuspexUmagent (auto start, restart-on-failure,
# --log <dir>\suspex_agent.log, firewall profile=any), start them.
.\install_agent_service.ps1 -Token <long-random-string>
```

What it sets up, spelled out for manual reproduction:

```
sc create SuspexAgent binPath= "C:\suspex\suspex_agent.exe --port 50074 --token <secret> --log C:\suspex\suspex_agent.log" type= own start= auto
sc description SuspexAgent "Suspex0 authorized-lab assessment agent (gRPC :50074)"
sc failure SuspexAgent reset= 300 actions= restart/5000/restart/5000/restart/15000
sc failureflag SuspexAgent 1
netsh advfirewall firewall add rule name="Suspex0 Agent" dir=in action=allow protocol=TCP localport=50074 profile=any remoteip=127.0.0.1,192.168.0.0/16,10.0.0.0/8
```

Rules of thumb:

- **binPath points at the exe itself.** Flags follow the exe path. A
  `cmd /c` wrapper is what produced 1053 (`ERROR_SERVICE_REQUEST_TIMEOUT`)
  on the rig: `cmd.exe` never calls `StartServiceCtrlDispatcher`.
- **No `--dev` in service mode.** `--dev` opts out of the SCM dispatcher
  AND out of the stdio-to-NUL safety redirect. It is for interactive
  console debugging only.
- **`--log <path>` always.** 4 MiB rotating (`<path>.1` keeps the previous
  generation), receives agent lines and gRPC-internal diagnostics. This is
  your post-mortem from session 0.
- **Firewall `profile=any`.** NIC flaps can move an interface between
  Public/Private/Domain profiles; a profile-scoped allow rule silently
  stops matching. Adjust `remoteip=` to your lab scope (or `any`).

### Static-IP pin (DHCP/NIC churn)

If the rig changes addresses across reboots/leases, pin the adapter:

```
... suspex_agent.exe --port 50074 --token <secret> ^
    --pin-adapter "Ethernet 2" --pin-address 192.168.56.31 --pin-prefix 24 ^
    [--pin-gateway 192.168.56.1] [--pin-debounce-ms 5000]
```

Applied at service start and re-applied (debounced) on
`NotifyUnicastIpAddressChange`. A hold marker (`SUSPEX_NET_PIN_HOLD` env
var, or `--pin-hold-marker <path>` existing file) silences re-pins during
deliberate flap tests. State is queryable over gRPC via the `NetPin`
service (`Status`/`Apply`, `apply` honors `clear_hold`).

## Provision (scheduled-task fallback)

When SCM cannot be used, a task works — but run the exe directly (no
`cmd /c`), as SYSTEM, at boot, with restart-on-failure and `--log`:

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\suspex\suspex_agent.exe" `
           -Argument "--port 50074 --token <secret> --log C:\suspex\suspex_agent.log"
$trigger = New-ScheduledTaskTrigger -AtStartup
$set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
           -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
           -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "suspex-agent" -Action $action -Trigger $trigger `
           -Settings $set -Principal $principal
```

`-ExecutionTimeLimit 0` matters: the default 72h limit kills a healthy
agent. The exe started outside SCM without `--dev` detects the
non-SCM parent and falls back to console mode automatically.

## One canonical autostart

The SCM service (`SuspexAgent`, `start= auto` + `sc failure` recovery) is
the ONLY autostart. Remove any legacy workaround on a rig — an onstart
scheduled task (`cmd /c ... --dev`), and especially a netstat watchdog
task that re-launches it: on this rig those leftovers duplicated agents
(one orphaned `--dev` instance held the port bound to a stale address
while a fresh instance failed with `No address added`), raced the service
at boot (the "dies silently on ~half the boots" signature), and survived
invisibly because they ran outside SCM.

```
schtasks /change /tn suspex-agent /disable
schtasks /delete /tn suspex-agent /f
schtasks /delete /tn suspex-agent-watch /f
```

`install_agent_service.ps1` now does this automatically. The watchdog's
job (revive a dead endpoint) is owned by: `sc failure` recovery for
process death, and the agent's built-in listener self-test — loopback
**plus every up-adapter IPv4** (catches LAN-only SYN drops that loopback
misses) — which rebinds once, and exits the process for SCM restart if it
wedges twice within 10 minutes.

## Verification & triage

**Never run `install_agent_service.ps1` through the agent's own
`exec_manage run_powershell` while it recreates the agent service** —
stopping the agent reaps the exec child mid-script, leaving the service
deleted (this exact failure stranded a rig once: agent down, umagent up).
Run it from a rig console, or via `exec_manage run_detached` (detached
children survive agent restarts). The script waits for a full stop before
`sc delete`, so the graceful-stop → marked-for-delete race is handled.

```powershell
# listener answers locally?
Test-NetConnection 127.0.0.1 -Port 50074
# process + port ownership
netstat -ano | findstr 50074
# service state + recovery policy
sc query SuspexAgent; sc qfailure SuspexAgent
# self-test + gRPC diagnostics since last wedge
Get-Content C:\suspex\suspex_agent.log -Tail 50
```

Manual unblock (old-style, still valid — should be rare now):

```powershell
taskkill /f /im suspex_agent.exe
sc start SuspexAgent
Test-NetConnection 127.0.0.1 -Port 50074
```

What you should see in the log after a NIC-churn episode: `gpr ...`
connection-error chatter, then `listener self-test miss ...` lines, then
`listener self-test FAILED 3x ... — requesting rebind` +
`listener wedge confirmed — rebuilding (generation 2)` and a fresh
`listening on 0.0.0.0:50074 ... [rebound]`. Clients reconnect on their
next attempt; the orchestrator's observed-endpoint self-heal covers a
changed address.
