# KDNET — kernel debugging over the network for the lab VM

`scripts/enable_kdnet.ps1` brings up Windows kernel debugging (kdnet /
`bcdedit /dbgsettings net`) inside the target VM so a host-side kd can
attach. Run it **elevated on the target**, not on the host:

```powershell
# inside the lab VM (elevated)
.\enable_kdnet.ps1 -HostIP 10.0.2.2 -Port 50000
# host-side, after the VM reboots:
kd -k net:port=50000,key=1.2.3.4     # or: windbg -k net:port=50000,key=1.2.3.4
```

`-HostIP` is the address of the machine running kd **as the guest sees
it** — under VirtualBox NAT that's `10.0.2.2` (the NAT gateway); on a
bridged/host-only lab net use the host adapter's real IP. `-Key` is the
four-part kdnet session key (`a.b.c.d`); keep it stable per-VM so saved
kd workspaces keep working, and change it if the port is reachable from
anything but the host. `-BusParams 'b.d.f'` exists for NICs bcdedit
can't self-select (run `kdnetlist.exe` on the host to see what's
supported). `-Off` runs `bcdedit /debug off` and drops the dbgsettings.

`/debug on` only takes effect on the **next boot** — the script never
reboots the box for you. Drive the VM from the host with
`D:\vmbox\hvlab_ctl.ps1` (`reset` for a hard poweroff, `restore <snap>`
to roll back to a pre-kd snapshot).

## When to reach for it

- **Bring-up** — hypervisor/driver work that BSODs before the suspex
  agent can report anything. A boot-attached kd catches the bugcheck
  live: `!analyze -v`, the raw trap frame, the driver stack. This is
  what `dump_manage(action='latest')` reconstructs *after* the fact;
  kd gives it to you *while* the box is dying, including hangs that
  never produce a dump.
- **Wedge forensics** — when the agent dies and `crash_state` shows a
  wedge instead of a reboot, an attached kd still answers: break in,
  `!stacks`, find the thread holding the lock. Without kd a silent
  wedge is just silence.
- **HW breakpoint hits** — `bp_manage(action='events')` kernel path
  hangs an int1 handler off a per-CPU IDT copy. Under a hypervisor that
  intercepts `lidt` (Hyper-V descriptor-table exiting + EPT-RO IDT) the
  install is refused with `STATUS_NOT_SUPPORTED` and `mode='auto'`
  falls back to the DbgEng **debug-port** bridge — monitor-mode attach
  to the bp's pid, mirror `ba` data breakpoints, hits drain through
  `debug_manage(action='events')` as `via='debug_port'`. That fallback
  covers pid-scoped **user-space** bps only. With kd attached, kernel-
  and global-scope hits are visible in the kd console directly, so the
  debug-port path matters mainly for the kd-less / hypervisor case.

## What it costs

kd is not invisible, and this stack measures things that notice:

- `target_manage(action='status')` / `host_info` report
  `kernel_debugger` (NtQuerySystemInformation
  KernelDebuggerInformation) — any sample with an anti-debug probe sees
  it too.
- `patchguard_state` reports **`kd_disables_pg`**: an attached kd
  suppresses PatchGuard, so driver behavior that PG would have
  bugchecked for (`.text` patches, stray hook installs) silently
  *works* under kd. Results you get with kd attached can be impossible
  on a clean boot.
- Boot timing and memory layout shift slightly (KD transport driver,
  extended kernel data).

**Rule of thumb:** enable kdnet for bring-up and wedge forensics, then
`enable_kdnet.ps1 -Off` + reboot (or restore the pre-kd snapshot) before
any final stealth/anti-analysis validation run. Treat `status` showing
`patchguard_state='expected'` as the gate for "kd is really gone".

## Topology note

kdnet is UDP from guest to host. Under VirtualBox NAT the guest can
reach the host but the host can't initiate inbound — that's fine, kdnet
is guest-initiated. On host-only/bridged networks either direction
works; just point `-HostIP` at wherever `kd -k` is listening.
