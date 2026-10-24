# Changelog

Version history and rebuild recipes for the suspex0 stack. Entries are
reverse-chronological; each header calls out which of `driver`, `agent`, or
`orchestrator` must rebuild.

## v0.31 — field-feedback hardening (orchestrator + agent + driver rebuild)

Phased delivery of the eleven-finding review plus the owner's two-cents
network self-heal. Each phase ships independently; the recipe below says
which component needs a rebuild per phase.

### Phase 1 — orchestrator only (server restart, no target rebuild)

- **Focus & connect ergonomics.** `target_manage(action='connect')` now
  sets the caller's focus to the newly-connected view by default
  (`focus=True`); opt-out preserves an existing focus. Dead-view errors
  (`require_client`) echo the view's last-known endpoint. The connect
  path probes every candidate (configured + last-good + registry
  observed + alt_hosts) in parallel instead of serially, so one dead
  endpoint no longer stalls another live one. The attach path now
  verifies the cached channel with a status() before returning it;
  machines_register warns when the alias looks like an IP already seen
  under a live computer_name (k205/k207/k206 litter).
- **Registry self-heal.** New `observed_endpoints[]` per machine
  (`host`, `port`, `seen_at`, `boot_epoch_ms`). Every successful connect
  records the endpoint it reached; Session.connect's candidate list
  consults these as additional probes so a DHCP-moved box self-heals in
  one round-trip. YAML aliases participate; the field is pure learned
  metadata and never shadows reviewed config.
- **exec timeout honesty.** `run_exe`/`run_powershell`/`run_cmd`/
  `run_script` now derive `timeout_ms` from `timeout_s` when the caller
  only raised the outer deadline, capped at the MCP response budget.
  `_RUN_DEADLINE_HINT` names both deadlines and the `run_detached`
  escape.
- **Watchdog safety.** Bare `arm` without a kicker now **refuses** with
  `kind='watchdog_no_kicker'` and auto-disarms the slot before replying
  (breaking: v0.17's warn-only path becomes the refusal). Pass
  `unsafe_without_kicker=true` to arm fire-and-forget; `id=0`
  auto-allocates the first free slot in 1..64.
- **`mem_rw(action='follow_chain')`.** Orchestrator-side pointer-chain
  walker — takes `address`, `offsets=[0x18, 0x30, ...]`, optional
  `pid`/`space`/`terminal_size`, and `expect_ascii` / `expect_nonzero` /
  `expect_module` per-hop validators. Reports every hop + the terminal
  read; typed `failed_at` names the first bad hop. No proto change.
- **`target_manage(action='timeline')`.** Merged chronological view
  (`since_iso`/`until_iso`) stitching boot identity, recent orchestrator
  op log, watchdog state, and pending boot notices into one response.
- **Symbol pattern fallback.** `symbols_manage(action='resolve',
  fallback='pattern')` now consults a curated signature pack
  (`orchestrator/src/suspex/symbols_patterns.py`) when the PDB server
  has nothing — seeded with `ObpRootDirectoryObject`,
  `PsLoadedModuleList`, `KdDebuggerDataBlock`, `KdpDmTransport`.
  Resolved VAs carry `source:'pattern'` + confidence (`low`/`high`).
- **PowerShell quoting.** `run_powershell command=...` now auto-routes
  multi-line / long / non-ASCII bodies through the `run_script` upload
  path (file-based, quoting-proof).

### Phase 2 — agent + proto (agent rebuild, no driver change)

- **Network identity echo (claim 1 feeder, 2.1).** `HostInfo` + `Status`
  now carry `ipv4[]` from `GetAdaptersAddresses`
  (`adapter`/`address`/`prefix_len`/`origin`/`gateway`/`mac`/`up`). The
  orchestrator records every up-adapter IP as an observed endpoint on
  connect — a NIC flap to another lease self-heals without any
  configuration change.
- **Static-IPv4 pinning (owner's 2 cents, 2.2).** New
  `agent/src/host/net_pin.{hpp,cpp}` and agent config
  (`pinAdapter`/`pinAddress`/`pinPrefix`/`pinGateway`/`pinDebounceMs`/
  `pinAtBootOnly`/`pinHoldMarker`). Disabled unless `pin_adapter` is
  set. Applies at service start and on
  `NotifyUnicastIpAddressChange` with a debounce; honored only on the
  named adapter; the hold marker (`SUSPEX_NET_PIN_HOLD` env or marker
  file) silences the re-pin for the duration of a deliberate flap.
- **Exec transport fixes (claim 7, 2.3).** `RunShellRequest` gains
  `encoded_command` (base64 UTF-16LE) — PowerShell goes through
  `-EncodedCommand` by default on new agents (immune to the double-parse
  mangling). The classic `-Command <quoted>` path now also forces
  `[Console]::OutputEncoding = UTF8` to kill the `â†’` mojibake.
- **`target_manage(action='rediscover')` (claim 1, 2.4).** Parallel
  probe of a machine's known endpoints (configured + observed +
  alt_hosts + hostname resolution). Records every answering host under
  `observed_endpoints`, so the next connect candidate list has it; the
  caller follows up with `reconnect` to swap the live channel. Full MAC-
  filtered ARP scan arrives with the agent-side 2.1 adapter list.

### Phase 3 — driver (driver rebuild + reload; crash-risk gate)

- **`obj_enum` addresses (claim 3, 3.1).** `ObjEntry` gains
  `address`/`type_index`/`source`. The driver resolves each named
  Driver/Device object's body VA via `ObReferenceObjectByName`
  (`source: 'walk'`), falling back to the `ZwQueryDirectoryObject`
  path (`source: 'zwquery'`) when the name doesn't resolve. The hash-
  bucket walk variant is wired through the ABI but gated to the
  resolver that is PatchGuard-safe.
- **`pool_scan` coverage + cursor (claim 4, 3.2).** `PoolScanRequest`
  gains `cursor`; pattern cap raised to 64 B, span cap raised to
  64 KiB. `PoolScanResponse` gains `holes` (previously silent
  content-read failures at `Pool.c:213`), `span_truncated`,
  `last_index`, and `next_cursor` — a wide sweep is now provably
  complete or partial-with-reasons, and the cursor drives resumable
  scans without the max_results silent cliff.

### Phase 4 — leak_scan primitive

- **`mem_rw(action='leak_scan')`.** Cross-scope needle sweep.
  `scopes=['kernel_pool','module_data','per_process']` × `needles=[...]`
  (byte strings or `hex:...`). Pool scope uses the cursor-paginated
  `pool_scan`; module scope reads each module's load range once per
  needle; per-process scope walks each process's heaps. Each scope
  reports `coverage` honestly (holes, span truncation, read failures),
  with aggregated `hit_total`.

### Phase 5 — listener & autostart hardening (agent + umagent + scripts; rig field report)

Field report from the rig: after NIC flap cycles the agent stayed alive
with the port LISTENING while every new SYN (loopback included) timed
out — only `taskkill` + restart recovered it — and boot autostart was
unreliable. Four fixes, all in the agent and umagent (no driver/orchestrator change):

- **Stdio can no longer wedge the accept path.** Root cause pattern:
  `cmd /c suspex_agent.exe --dev ...` under a scheduled task gives the
  agent session-0 pipes nobody drains; gRPC logs connection errors to
  stderr during network churn, the pipe fills, and the thread inside the
  blocked write (event-engine/accept path included) stalls. New
  `agent/src/srv_log.{hpp,cpp}`: `--log <path>` rotating file (4 MiB
  default, `--log-max-mb`), stderr spliced onto a drain pipe and relayed
  into it at both the CRT and `SetStdHandle` level (covers native and
  stdio writers; the classic `gpr_set_log_function` sink no longer exists
  in current gRPC), and stdout/stderr redirected to `NUL` in service/task
  context (`--dev` keeps console stdio). Linked into both agent and
  umagent.
- **Bind retries instead of exiting.** `BuildAndStart` failures (stale
  instance still holding the port after a NIC flap removed its address,
  transient `WSAEADDRINUSE`) now retry with 0.5s→15s backoff in a
  generation loop instead of terminating the process.
- **Listener self-test + self-rebind.** New
  `agent/src/listen_watch.{hpp,cpp}`: raw loopback TCP connect every 15s
  (deliberately below gRPC — the wedge leaves the port LISTENING); after
  3 consecutive dead probes the server is shut down with a deadline and
  rebuilt — fresh socket, dead client connections reaped. The SCM stop
  path is now graceful too (`SetServiceStopHook`: server shutdown,
  breadcrumb flush, then `SERVICE_STOPPED`; `ExitProcess` remains as a
  bounded backstop), and the service registers under the name SCM
  actually dispatched (a mismatch silently killed ServiceMain before).
- **Boot autostart + honest provisioning.**
  `scripts/install_agent_service.ps1` now defaults to `start= auto`
  (`-StartMode demand` opts out), adds SCM failure recovery for the
  umagent (agent already had it), adds `--log` to both binPaths, and the
  firewall rules carry `profile=any` + `-RemoteIp` (a profile-scoped
  rule went silent after NIC flaps moved the interface profile). New
  `docs/AGENT_DEPLOY.md` runbook: service install (binPath points at the
  exe — never `cmd /c`, which is what failed the SCM handshake with
  1053), scheduled-task fallback XML-equivalent settings, static-IP pin
  wiring, and the loopback triage/unblock commands.

Also: **Phase 2.2 completion** — `net_pin.{hpp,cpp}` was present but
unwired. Now built, configured (`--pin-adapter/--pin-address/--pin-prefix/
--pin-gateway/--pin-debounce-ms/--pin-at-boot-only/--pin-hold-marker`),
started at agent boot, and exposed over the new `NetPin` gRPC service
(`Status` snapshot / `Apply` one-shot re-pin with `clear_hold`). And the
agent version constant moved from the stale `0.10.0` to `0.31.0` — the
`+<sha>-dirty` suffixes in field reports now match the changelog.

### Phase 5 follow-up (rig reboot war, 2026-10-24)

Post-deploy field evidence drove four more hardening changes:

- **Self-test covers LAN addresses too.** The wedge report included
  LAN-only SYN drops with loopback answering — a probe set of just
  `127.0.0.1` is blind to WFP/profile-scoped inbound drops (SMB keeps
  answering via its own all-profile rules). The watch now enumerates
  every up-adapter IPv4 each cycle (fresh per DHCP churn) and strikes on
  any dead target, logging which one.
- **Wedge escalation to SCM.** In-process rebind once; if the listener
  wedges (or `Wait()` returns unrequested) twice within 10 minutes, the
  agent logs and exits(1) so `sc failure` recovery supplies a fresh
  process. The orphaned-instance class of failure (a process alive but
  unreachable forever) is now bounded by construction.
- **Log no longer dies silently.** A transient lock on the log file at
  (re)open made every `Logf` a silent no-op for the process lifetime —
  the rig ran a whole night with an unlogged agent (SCM said RUNNING,
  zero log lines). `Logf` now lazily re-opens every 10s and announces
  `(log reopened after N failed open attempts)` once it gets through.
- **One canonical autostart.** The rig carried an onstart
  `cmd /c --dev` task plus a 5-min netstat watchdog task that re-ran it —
  the source of duplicate/stale instances, boot races and the
  `No address added` bind failure. `install_agent_service.ps1` now
  deletes `suspex-agent` and `suspex-agent-watch`; the SCM service (auto
  + failure recovery + `--log`) is the only autostart, documented in
  `docs/AGENT_DEPLOY.md`.

### Rebuild recipe

- Phase 1: restart `orchestrator-server`. No agent/driver change.
- Phase 2: rebuild `agent` + regenerate protos
  (`scripts/update_target.py --component agent`). Driver untouched.
- Phase 3: rebuild `driver` + regenerate protos; reload the driver via
  `target_manage(action='driver_load')`. **Sacrificial-box validation
  first** — the `obj_enum` resolver and the `pool_scan` cursor are new
  kernel code paths.
- Phase 4: no additional rebuild; ships with Phase 1 orchestrator but
  benefits from Phase 3 driver (`next_cursor` for complete coverage).
- Phase 5: rebuild `agent` + `umagent` (proto bump: `NetPin` service —
  regenerate stubs, `scripts/build.ps1 -Target user` does it) and
  re-run `scripts/install_agent_service.ps1` on the rig so autostart,
  recovery, `--log` and `profile=any` take effect. No driver change.

## v1.0 — first public release

Initial public release of the suspex0 stack (driver, agent, orchestrator).
The feature surface is the v0.29 set; entries below are the private
development record, kept as history. The optional `codegen` extra installs
Keystone/Unicorn separately and they are not vendored here.

## v0.29 — two-day-lab feedback round (orchestrator only; no driver/agent rebuild)

Ergonomics + triage fixes from living in the MCP for a two-day engagement
(crash forensics, HV debugging, regression runs). Every change is
orchestrator-side; takes effect on the next server restart.

- **dump_manage stack — triage callstack + driver list in one verb.** New
  `action='stack'` walks the dump's saved stack end to end, pulls KernBase
  out of the embedded debugger-data block (+0x18), parses the triage
  driver list (0x90-byte `DUMP_DRIVER_ENTRY` records; name/base/size), and
  attributes every frame — all offline, so stale-boot dumps resolve.
  Layered live-map symbolization (`nt!sym+0xN`) when connected + same-boot.
  Frame walk is offline-first: `driver_list` → `kernbase_range` →
  `unresolved`/`data`.
- **Triage TopOfStack region fix.** The saved callstack covers
  `[TopOfStack, TopOfStack + SizeOfCallStack)` — TopOfStack is the
  capturing thread's Rsp, not the region end. The old `[top-size, top)`
  reading matched nothing, which emptied `stack_qwords` on every real
  minidump. `parse` now walks up to 32 qwords from Rsp on real triage
  dumps, and falls back to walking the whole saved region when Rsp is
  outside it. Fixture/unit tests updated to the pinned semantics.
- **Hex mirrors on dump output.** `parse`/`latest`/`stack` emit
  `params_hex`, `context_hex` (every register), `faulting_va_hex`,
  `faulting_pc_hex`, `watchdog_hex`, and per-qword `va_hex`/`value_hex`
  next to the decimal originals — no value_manage round-trips to eyeball
  an address.
- **Discoverability: every `_unknown_action` embeds the per-verb
  one_liners** under `data.actions`, and an empty `action=` IS the help
  response. A mistyped verb now answers "what should I have called?" in
  one round trip across all 19 group tools.
- **symbols_manage lookup confidence.** Nearest-match displacement above
  `max_disp` (default 0x1000) flags `confidence:'low'` + a "treat the
  name as a guess" warning instead of confident-looking junk
  (MmSetBankedSection+0x8E27).
- **watchdog auto_arm status surfaced.** The re-arm-on-driver_load/
  new_boot hook is config-gated and was silent when unconfigured —
  `watchdog_manage(action='list')` and every `driver_load` response now
  carry `watchdog_auto_arm` (`configured:false` + how to enable).
- **target_manage boot_recover.** The post-reboot choreography as one
  call: verify/restore the view, sweep stale boot state, load the driver
  if it did not survive, re-arm watchdog.auto_arm, pull + parse the
  newest minidump (`load_driver`, `include_dump` params).
- **file_manage read text mode.** Text-shaped files (.txt/.log/.ps1/.md/
  .json/...) return a `text` field automatically (256 KiB preview cap,
  ranged reads beyond); `decode=` still wins for typed values.
- **exec transport honesty.** `run_detached` output now carries the
  exit-only CRT-buffering warning up front (it hid in `detached_follow`);
  `run_cmd`/`run_powershell` help spells out the double-parse quoting
  mangling and points at `script_b64=` / `run_script`; a job-name-looking
  `name=` gets a "name selects a target VIEW, not a job label" hint.
- **findings_manage deprecation is visible.** The forwarding alias stamps
  a `warnings` entry into the response body (the server-side log line
  never reached MCP clients).
- **connect endpoint fallback.** New `TargetConfig.alt_hosts` (also on
  `machines:` blocks); on pre-flight probe failure connect tries the
  last host that actually connected (in-memory) then `alt_hosts`, and
  reports `endpoint_fallback {configured, tried, used}`. Kills the
  probe-by-hand step when the NIC lease flaps (.167/.196).
- **wait_connectable deadline guidance.** Help + response note when
  `timeout_s` exceeds ~60s: the MCP host's own request deadline kills
  the call first (-32001) — loop short waits instead.

## v0.28 — ghidra_manage: second analysis engine (orchestrator only; off by default)

`ghidra_manage` is a first-class sibling of `ida_manage` backed by headless
pyghidra — usable instead of IDA when idalib is unavailable, or alongside it
for a second decompiler opinion and P-code.

- **Same orchestration contract** — `open | open_async | open_status |
  list | close | schemas | tools | health`, MRU session autofill,
  name-collision suffixing, share/co-ownership, `force` close, manifest
  persistence (`~/.suspex0/ghidra_sessions.json`), background jobs
  (`ghidra_job_*`) and oversized-result chunking — the IDA call shapes
  carry over by renaming the tool.
- **One shared JVM + one shared Ghidra project** hosts N program sessions
  (vs. idalib's backend-per-idb): opens after the first skip JVM start;
  a JVM crash drops all ghidra sessions together, which the manifest
  reopens. `close` saves+releases; `close(purge=true)` deletes the program
  from the project.
- **Tool surface** — decompile (batch + callees/strings/xrefs), disasm,
  `pcode`/`get_pcode`, xrefs, callgraph, imports/exports/entry-points,
  segments/read_bytes, strings + `search_code`, symbol search,
  pattern/qword scans, function create, rename function/variable,
  retype, set prototype, comments, patch_bytes, type queries
  (`type_info`, `get_struct_member`, `resolve_offset`,
  `analyze_struct_detailed`, `list_data_types`), `dump_layout` writing
  the same `pdb_layout_cache` schema symbols_manage consumes, analysis
  status probes, and `exec_ghidra_script` as the exec_idapython
  counterpart.
- **Ledger/knowledge parity** — `ida_sessions` gained an `engine` column
  (migrated in place; existing rows stay `'ida'`); ghidra sessions record
  as `ghidra:<name>` so `knowledge_manage(action='about', artifact_sha=…)`
  shows cross-engine work on the same binary. `ghidra_manage` breadcrumbs
  land in `tool_events` like ida_manage's.
- **Dormant until configured** — `ghidra.enabled: false` is the default;
  the tool stays registered and answers a typed "disabled" error. Enable
  needs a Ghidra install (`ghidra.ghidra_dir` → `GHIDRA_INSTALL_DIR`), a
  JDK (`ghidra.java_home`), and `pyghidra`+`mcp` in the backend env
  (`uv sync --extra ghidra`, or point `ghidra.backend_python` /
  `.ghidra-venv` at it). See the `ghidra:` block in
  `configs/example.yaml`. New: `orchestrator/pyghidra_ext/` backend,
  `orchestrator/ghidra_shim/` supervisor, `src/suspex/ghidra_bridge/`
  bridge.

## v0.27 — canonical artifact store, MMIO read-fault taxonomy, nibble wildcards (orchestrator + agent/umagent/tools via comm; no ABI/proto bump)

Three engagement-feedback fixes: the two-artifacts-dir split that made
`bin_manage`/`ida_manage` unable to see `dump_module` output, kernel-read
failures on BAR-backed pages being reported as a missing driver, and
`pattern_scan` rejecting nibble wildcards.

### One artifact namespace

- **`config.artifacts_dir()` anchors at the repo root** — a bare
  `artifacts.dir: artifacts` used to resolve against whatever cwd the
  server launched with, so two launches wrote two stores
  (`<repo>/artifacts` vs `orchestrator/artifacts`) and each consumer's
  relative join picked one at random. `_project_root()` anchors every
  relative artifact path (`artifacts.dir`, `reports_dir`, `pdb_cache`
  via new `pdb_cache_dir()`); absolute paths and the
  `SUSPX_ARTIFACTS_DIR` / `SUSPX_MCP_SPILL_DIR` env overrides pass
  through unchanged.
- **`mcp/_artifacts.py` (new)** — `resolve_artifact_path()` maps every
  spelling onto the canonical store: `dumps/x.sys` (the `path` field of
  `list_artifacts`), `abs_path` verbatim, `artifacts/dumps/x.sys` (the
  leading store prefix is stripped, not double-rooted), and
  `spill/<sha>.bin` routed to `spill_dir` even when
  `SUSPX_MCP_SPILL_DIR` relocates it outside `artifacts/`. Containment
  rejects traversal outside both roots; missing-but-contained paths
  resolve (caller picks `not_found` vs `bad_arg`).
- **Whole-store sha index** — `find_artifact_by_sha()` covers dumps/,
  ingested/, spill/, and `store_binary` workdirs, so `sha256=` lookups
  stopped being spill-only. Wired into `bin_manage` (`sha256=`/`path=`/
  `diff compare_path`), `file_manage` (`read`, `grep_artifact`,
  `read_artifact`), `dump_manage parse`, `symbols_manage`,
  `knowledge_manage about`, `ida_manage open/open_async`, and
  `read_slice` (new `path=` escape). Repro that now works:
  `dump_module` → `bin_manage(action='info', path=<returned>)`.

### MMIO/BAR read faults are `invalid_address`, not `driver_absent`

- A page-table-mapped kernel VA backed by device memory fails
  `MmCopyMemory` with NTSTATUS whose Win32 projection is `gle=59`
  (`UNEXP_NET_ERR`) or `gle=1117` — the same `driver: DeviceIoControl`
  prefix a genuinely-absent driver produces, so the driver catch-all
  was claiming a healthy driver was missing. `_error_enrich` gains a
  rule (gle 59/1117, `UNEXP_NET_ERR`, `IO_DEVICE`,
  `STATUS_UNEXPECTED_IO/NETWORK_ERROR`, `0xC00000E9`/`C4`/`185`)
  ordered BEFORE the driver rule; `_looks_invalid_addr` recognizes the
  same set; `WIN32_ERRORS[59]` names it. The hint now says what the
  failure means and offers `va_translate` / `space='physical'` at the
  PA instead of `driver_load`.
- **comm surfaces the raw NTSTATUS** — `Driver::Fail` appends
  `nt=0x%08lx` read via `RtlGetLastNtStatus` (lazy `GetProcAddress`, so
  targets not linking ntdll build unchanged). The Win32 projection
  flattens `STATUS_UNEXPECTED_IO_ERROR`→59; the nt suffix keeps the
  real code in the error text and classifier.

### Nibble wildcards in pattern_scan

- `parse_mask` accepts `6?` (high nibble fixed) and `?F` (low fixed)
  alongside `4D`/`??`; the pattern byte carries the pinned nibble and
  the mask gains `H`/`L` chars. `sdk.pattern_scan` compares only the
  constrained nibble(s). Bad tokens raise `SuspexError` (surfaced as
  `bad_arg` by `scan_start`/`pattern_scan`/`pool_scan` instead of
  propagating raw).
- The agent wire mask is byte-granular, so
  `sdk.scan.agent_pattern_scan()` downgrades `H`/`L` to `?` for the RPC
  and post-verifies each returned candidate via `mem_read` (bounded
  4x-result over-fetch; nibble hits are a strict subset). Used by the
  `mem_rw pattern_scan` whole-space path and `MemoryView.scan`.
- `pool_scan` refuses nibble masks with `bad_arg` — the driver's pool
  matcher is byte-granular and would silently treat `H`/`L` as exact.

### Registry

- `KNOWN_KINDS` registers the `bin_manage` async-engine slugs shipped
  post-v0.26 (`analysis_running`, `analysis_ready`, `unknown_job`,
  `engine`) — the `test_f_2` drift guard was red on HEAD.

**Rebuild recipe:** orchestrator is pure-Python — restart the server.
comm changed (`Driver::Fail` nt= suffix): rebuild `suspex_comm` and
relink `suspex_agent`, `suspex_umagent`, `mapper`, `drv_exerciser`, then
`scripts/update_target.py --component agent|umagent`. No driver change,
no wire bump.

## v0.26 — direct function calls on the live target (driver + agent + umagent + orchestrator; ABI v13 / proto v15)

`Exec.CallFunction` (gRPC v15) + `exec_manage(action='call')` — call an
arbitrary function in target context and read its return value, on both
views, in both spaces. Rebuild recipe: `driver + agent + umagent +
orchestrator; ABI v13 / proto v15` (README "ABI v13 rebuild").

- **User calls (shared trampoline)** — `agent/src/exec/call_user.cpp`
  compiles into both `suspex_agent` and `suspex_umagent`: a one-page param
  block (params at base, 107-byte ml64-assembled position-independent stub
  at +0x200, listed in the file with its asm) is injected into the pid with
  a remote thread. Returns rax + TEB LastErrorValue. No SEH in the stub —
  a callee exception exits the thread with the NTSTATUS as exit code and is
  reported as `exception`. WOW64 pids refused (`bad_target`). Pointer args
  are caller-marshalled (`mem_rw alloc` + `write`, pass the VA).
- **Timeouts are leaks that stay inspectable** — on timeout the thread is
  deliberately left running; the response carries `thread_tid` + `stub_va`
  (the param page; free via `Memory.Free`). `kill_on_timeout` opts into
  TerminateThread + free.
- **Kernel calls (driver work item)** — new `SUSPEX_IOCTL_KERNEL_CALL`
  (func 0x8B0): the driver runs the target inside a WDF work item at
  PASSIVE_LEVEL in System context under `__try/__except` (rax + exception
  capture), KEVENT completion with caller timeout, sequential-queue
  serialization. Targets must sit inside a loaded kernel module unless
  `force`; non-canonical VAs refused. Hung targets wedge the slot — later
  calls report `STATUS_DEVICE_BUSY` honestly (no unwedge without reboot).
  PASSIVE_LEVEL-only contract (APC/DISPATCH-requiring routines are out).
- **Exerciser gate** — `drv_exerciser kcall --target <va> [--arg …]`
  exercises the IOCTL offline before any gRPC surface.
- **MCP surface** — `exec_manage(action='call', space=, address=, pid=,
  call_args=, timeout_ms=, kill_on_timeout=, force=, name='user'|'kernel')`:
  `address` resolves int / `0x…` / `module+offset` / `module!export`.
  Gated by `security.allow_function_call` (default **false**) — the
  strongest actuator in the stack, same posture as `allow_ioctl_send`.
- **Error taxonomy** — `not_allowed` (gate off), `bad_arg`, `bad_target`,
  `agent_old` (pre-v15 agent, UNIMPLEMENTED), `call_failed`,
  `not_connected` (named view missing); `status` field distinguishes
  `completed` / `exception` / `timeout` / `incomplete`.

## v0.25 — engagement round: crash triage, forensic verbs, file/exec gaps, write-path visibility (driver + agent + orchestrator; ABI v12 / proto v14)

The hypervisor-bring-up feedback round: BSOD triage without a manual
pull, silent write paths made visible, hands-off watchdog re-arm across
reboots, the `idt`/`dps`/`dt` forensic verbs, and a docs + tool-catalog
slimming pass.

### Crash triage

- **`dump_manage` (new tool)** — `parse` kernel crash dumps
  (DUMP_HEADER64: minidump/triage, kernel, full/bitmap) and usermode
  MDMP files into `{bugcheck:{code,name}, params[4], context,
  exception, stack_qwords}`; a suspex-watchdog bugcheck (0xE2)
  self-identifies as `fired_by:'suspex_watchdog'`, closing the
  "watchdog-fire vs spontaneous crash" question alongside the agent
  breadcrumb. `latest` lists `C:\Windows\Minidump`, signature-probes
  the newest `.dmp` with a ranged download, then pulls and parses it —
  the post-BSOD one-liner. Pointer fields resolve to `module!sym+off`
  on same-boot dumps; a dump that predates the current boot returns
  raw with `resolution:'stale_boot'` (opt back in via
  `assume_fresh=true`).
- **`crash_state` minidump block** — auto-pulls+parses the newest dump
  on `new_boot` (or `include_dump=true`), so the first post-reboot
  call answers `{bugcheck, params, faulting_module}` in one shot;
  failures attach `minidump_error` instead of breaking the rest.
- **`target_manage wait_boot_change`** — blocking verb: polls status
  internally with bounded backoff and returns on a
  `note_boot_identity` change, or `kind:'wait_timeout'` on expiry.
- **Boot monitor** — a background status poller on the primary view
  (default 5 s, `monitor.boot_poll_s` when configured) sweeps
  view-scoped state on reboot/agent-restart (follows, auto-kicks,
  attach leases, ownership tags), parks `pending_boot_notices` onto
  the next status call, and best-effort pre-pulls the newest minidump
  so `crash_state` is instant.

### Forensic verbs

- **`mem_rw resolve_range` (alias `dps`)** — dps-style pointer
  annotation over a range: every qword classified
  kernel/user/nonptr and resolved to module+rva (module!symbol
  best-effort); `filter='ptr'` default drops non-pointers, `'all'`
  dumps every row. Reads run partial so PTE holes truncate honestly.
- **`mem_rw dt`** — named-type read sugar:
  `value='_KTRAP_FRAME', module='ntoskrnl.exe', address=…` decodes
  exactly like `read decode={'type':…}` without the dict.
- **`mem_rw idt`** — per-CPU IDT dump with handler VAs resolved to
  `module!sym+off`; handlers outside the builtin allowlist
  (ntoskrnl/hal/kd/cng/ksecdd/suspex) get `suspicious:true` —
  hypervisor IDT detours light up by design. `all_cpus=true` shows
  per-CPU bases. Needs an ABI v12 agent; older agents return
  `kind:'agent_old'`.

### File/exec gaps, snapshots, watchdog auto-arm

- **`file_manage read`** — ranged remote read via the Download
  stream's offset/length fields; bytes return inline (`length=0` =
  to EOF, 4 MiB cap), `decode=` applies the `mem_rw` decode spec,
  and `side='orchestrator'` reads a local artifact path/sha256 with
  no target contact.
- **`download recursive=true`** — mirrors a remote directory tree
  into `artifacts/downloads/<sanitized>/` preserving relative
  layout (512-file and `security.max_transfer_mb` caps; per-file
  failures collect into `skipped`, not abort).
- **Snapshot pump** — `snapshots.ranges` config captures named
  PA/VA ranges on an interval into
  `artifacts/snapshots/<boot_epoch_ms>/` + `index.jsonl`: pre-crash
  state survives the BSOD. Periodic capture is the only honest
  shape — a wedged target can't answer reads, so failures append
  `{ok:false}` rows rather than crash the pump.
- **`watchdog.auto_arm` config** — re-arms hands-off wedge
  protection on `driver_load` and on post-reboot reconnect without
  a manual `auto_kick`; idempotent across reconnects, a foreign
  `watchdog_collision` surfaces as a warning.
- **exec polish** — `run_powershell`/`run_cmd`/`run_exe` accept
  `background=true` (routes through `run_detached`, returns a
  `handle_id`); `timeout_s` is an orchestrator-side per-call gRPC
  deadline; a `run_detached` DEADLINE_EXCEEDED now hints the spawn
  may have succeeded before you retry.

### Driver/agent/proto — ABI v12

- **Write-path reporting** — `MemoryWriteResponse.write_path`
  (`direct_va` | `phys_remap`): kernel writes no longer silently
  take the phys-remap fallback — a remapped write attaches a
  warning that DR watchpoints on that linear address did not see
  the store. `STRICT_VA` (`mem_rw strict_va=true` /
  `no_phys_fallback`) refuses the remap with
  `STATUS_INVALID_ADDRESS`; the pre-walk also closes the RO-page
  bugcheck the old probe-then-copy flow could hit.
- **`va_translate` gains `cr3=` + USER space** — caller-supplied
  CR3 overrides `__readcr3()`; pid-scoped user walks go through
  `KeStackAttachProcess` instead of returning NOT_IMPLEMENTED.
- **`Memory.IdtList`** — driver-side per-CPU `__sidt` +
  KIDTENTRY64 decode straight into `IdtEntryRow`s (no agent-side
  kernel-read round-trip per entry); `all_cpus` surfaces the
  per-processor bases.
- **Foreign-CR3 write** — `cr3 != 0` kernel writes pin the IOCTL
  thread to its CPU, swap CR3 under `__try`, copy with
  `RtlCopyMemory`, and restore in `__finally`.
- **Wire** — `MemoryWriteRequest +cr3 +flags`,
  `MemoryWriteResponse +write_path`, `VaTranslateRequest +cr3`,
  `SUSPEX_MEM_WRF_STRICT_VA=0x1`; `SUSPEX_ABI_VERSION` 11 → 12.
- **v14 agent surface** — `ListShells`, `mem_processes`
  `with_cmdline` (per-pid PEB walk), `thread_list` `with_context`
  (SuspendThread+GetThreadContext register snapshots), share-mode-0
  file reads/tails/hash via VSS shadow fallback, LogFollow
  `stat_only` metadata chunks for locked files, StatusResponse
  `boot_epoch_ms`. Orchestrator side: `process_list`/`threads`
  enumerate driver-free on the kernel view (the post-reboot
  pre-driver-load hole), error envelopes carry `received_args`
  (secret-redacted echo of what arrived — arg-stripping is
  diagnosable in one round trip), and a new `sharing_locked` error
  kind.

### Docs + catalog

- **`scripts/enable_kdnet.ps1` + `docs/KDNET.md`** — target-side
  kdnet bring-up for the lab VM (`-HostIP`/`-Port`/`-Key`/`-Off`,
  prints the kd.exe attach line) plus the trade-off written down:
  kd presence is a stealth confounder and `patchguard_state`
  already reports `kd_disables_pg`, so drop kd for final stealth
  validation.
- **README/SKILL discoverability pass** — named-type `decode=`,
  physical-space `disasm`/`strings`/`iocs`/`entropy`,
  `run_script background=true`, and every v0.25 verb are findable
  in one skim.
- **Tool-schema slimming** — `Field(description=…)` cut to one
  line each (detail lives in the `_*_ACTION_HELP` maps served by
  `action='actions'`) and tool docstrings reduced to a summary +
  pointer: the `tools/list` catalog drops ~55 KB → ~30 KB.

**Rebuild recipe (ABI v12):** `cmake --preset win64 && cmake
--build --preset win64-release`, then `scripts/sign_driver.ps1` and
`orchestrator/.venv/Scripts/python.exe scripts/update_target.py
--component all`. Orchestrator is pure-Python — restart the server.

## v0.24 — engagement-feedback fixes: hex RVAs, VA-dump PDB identity, PDB-apply visibility (orchestrator + agent; proto v13)

All nine items from the kernel-recon session feedback. Orchestrator-only
unless noted.

### High impact

- **`symbols_manage resolve`/`lookup` return hex-mirrored RVAs** —
  `rva`/`symbol_rva` joined the `HEX_ADDRESS_KEYS` set, so every
  response now renders `rva: "0xef0dc0"` + `rva_int: 15666624` (the
  same `_int`-mirror convention `mem_rw` uses). The bare-decimal
  `15666624 → 0xEF2C00` hand-conversion incident (wrong kernel
  addresses for ~15 minutes) can't recur.

- **`symbols_manage info/ensure/resolve/layout` parse `dump_module`
  output** — `read_pdb_info` read the CodeView blob via
  `PointerToRawData`, which the agent's VA-layout dumper zeroes (it
  keeps `AddressOfRawData` authoritative so dbghelp/IDA can parse the
  dump) — hence "no RSDS CodeView entry" on a healthy dump.
  `read_pdb_info` now tries `PointerToRawData` first (on-disk files)
  and falls back to the bare RVA (VA-layout dumps), with the section
  table as a third candidate. `ensure` also accepts an explicit
  `pdb_guid=`+`pdb_age=` (+`pdb_name=`) override for images whose
  debug directory is stripped — take the values from
  `bin_manage(action='info')`'s `pdb_path`.

- **PDB-apply visibility** — `open_status`/ready envelopes carry
  `open_elapsed_s`, and a pending open past `pdb_apply_warn_s`
  (default 300 s, config `ida.pdb_apply_warn_s`) gains a warning
  naming the escape hatches (keep polling / reopen with
  `run_auto_analysis=false` / `bin_manage` for pure-parse questions).
  "Applying for 20 min" and "wedged" are now distinguishable.

### Medium

- **`ida_manage open/open_async` accept artifacts-relative paths** —
  `path='dumps/ntoskrnl.exe'` (or `artifacts\dumps\...`) resolves
  against the artifacts dir like `file_manage`/`symbols_manage`
  already do; the error names both attempted locations.
- **`driver_unload` busy-check cross-checks the ClientRegistry** — a
  peer the registry shows as user-view-only (umagent) no longer blocks
  an unload; stale `session.refs` entries are pruned with a logged
  note (`drop_view_ref`). The busy envelope names what each peer
  holds (`held_by`: view refs + attach pids), and `list_peers` rows
  carry `session_view_refs` next to `connected_views` so the two
  ledgers' desync is visible.
- **`list_artifacts` covers dumps/ + ingested/** — rows carry the
  sha256 (cached per path+mtime+size) and artifacts-relative `path`,
  so `about`-by-sha and `bin_manage path=` work straight after
  `dump_module`; `knowledge_manage about` accepts `path=` directly.

### Low

- **ida shim schema-mismatch errors carry the expected fields** — a
  validation error now appends `expected args for <tool>: ...` from
  the cached inputSchema (with `required:`), so an
  `address`/`memory_address`/`function_address` mixup is fixed on the
  retry instead of costing a `schemas` round-trip per mistake.
- **`struct_info`/`resolve_member`/`enum_info` accept an empty or
  partial `build_id`** — empty resolves to the only installed layout
  for the module; unambiguous prefix/suffix matches resolve too;
  ambiguous/unknown ids fail with `installed_builds` listed.
- **`dump_module` reports a per-section residency map** — the dumper
  records `{name, va, size, dumped_bytes, complete}` per section and
  the response gains `sections` plus a `warnings` note naming
  partial sections; the generic "discarded PAGE/INIT" note is gone.

Rebuild: orchestrator is pure-Python (restart the server). Agent:
`cmake --build build --config Release --target suspex_agent`, then
`scripts/update_target.py --component agent`. Proto bumped (v13) —
wire-compatible (new fields only); no driver change.

## v0.23 — HW-BP hit observability: kernel trap hook + DbgEng debug-port fallback (driver + agent + orchestrator; ABI v11 / proto v12)

The "blind breakpoints" gap is closed: `bp_manage` armed DR0-3 but hits
were only visible with an attached kd. Two delivery paths now exist:

- **Kernel path (non-hypervisor targets)** — the driver carries an
  int1 trap hook that appends BP_HIT records to the existing notify
  ring; the agent drains them through `Events.Poll`/`Stream`.
- **Debug-port path (hypervisor guests / user processes)** — the
  agent's DbgEng session arms equivalent data breakpoints and reports
  each hit as a `bp_hw` event through `debug_manage(action='events')`.
  `bp_manage(action='events', mode='auto')` tries the kernel path
  first and falls back automatically when the hook is unsupported.

- **Driver: per-CPU IDT-copy hook** (`BpTrap.c` + `BpTrapAsm.asm`) —
  installed lazily on the first BP-class subscription that carries
  `SUSPEX_NOTIFY_FLAG_BP_HOOK_OK`. Each CPU's IDT is copied into
  writable nonpaged memory with entry[1] retargeted at
  `SuspxBpTrapStub`; `KeIpiGenericCall` `lidt`s every CPU onto its
  copy at IPI_LEVEL. A **no-op `__lidt` probe** runs before install:
  Hyper-V guests apply descriptor-table exiting plus EPT read-only
  protection on the IDT (and CR0.WP interception), so the probe
  returns `STATUS_NOT_SUPPORTED` (0xc00000bb) instead of attempting
  an install that would fault. Kernel VEH and `KiDebugRoutine` were
  evaluated and do not exist on 26200; `.text` patching bugchecks the
  guest under Hyper-V — the probe gate is what keeps this lab-only
  feature from crashing hardened targets. The asm stub snapshots the
  trap frame, calls `SuspxBpTrapDispatch`, and either consumes the
  #DB (RF set, iretq) or chains to the saved `KiTrap01`. Dispatch
  matches DR6 B0-B3 against `SuspxBpTable` (pid/tid/global scope +
  live DRn content check) and appends `{rip, dr6, bp_id, slot,
  access, irql, pid, tid}` to the notify ring — no second ring, no
  new drain RPC. Hits at IRQL >DISPATCH_LEVEL record slot+address
  without taking `SuspxBpLock`; contention/teardown losses count into
  `SuspxBpTrapMissed` (surfaced as `bp_missed` in stats).
  `SuspxNotifyDisable` — called from both the NOTIFY_DISABLE ioctl
  and `EvtDriverUnload` — clears the BP class bit then uninstalls the
  hook with a bounded in-flight drain, so a driver stop can't leave a
  dangling IDT[1] entry pointing at freed pages.
- **Driver: debuggee-safe DR arming** (`BpHw.c`) — `PsSetContextThread`
  /`PsGetContextThread` wait on a special APC that never delivers while
  a thread is frozen (debug stop, `NtSuspendProcess`) or the process is
  debugged; since the device queue is sequential, one blocked ctx op
  wedged every ioctl behind it. `SuspxHwApplyFn`/`SuspxHwClearFn` now
  skip the context write/readback entirely when the process has a
  debug port (`PsGetProcessDebugPort`), the thread is frozen
  (`PsGetThreadFreezeCount`), or it is terminating. On a debugged
  process the remote kernel APC (`SuspxDrArmWorker`) is skipped too —
  the debug port owns the DRs and a driver-armed DR the debugger didn't
  set refires instantly on resume (an infinite #DB storm that
  livelocked the guest in testing); the DbgEng mirror bp covers the
  hits instead. `SuspxThreadCtxOp` (`Context.c`) fails fast with
  `STATUS_SUSPEND_COUNT_EXCEEDED` on frozen/terminating threads for
  every caller.
- **ABI v11** — `SUSPEX_EVT_KIND_BP_HIT=6`, `SUSPEX_EVT_CLASS_BP=0x8`,
  `SUSPEX_EVT` gains `Address/Dr6/BpId/Slot/Access/Irql`,
  `NOTIFY_SUBSCRIBE_IN.Flags` (`SUSPEX_NOTIFY_FLAG_BP_HOOK_OK`),
  `NOTIFY_STATS_OUT.BpTrapMissed` (was Reserved).
- **Proto v12 / agent** — `EVENTS_KIND_BP_HIT`, `SuspexEvent` hit
  fields, `EventsPollRequest.kinds_mask`+`dangerous_ok`,
  `EventsStreamRequest.dangerous_ok`, `EventsStatsResponse.bp_hook`/
  `bp_missed`, `AttachRequest.monitor`, `DebugEvent.pid`,
  `BpEntry.pid/tid/size`, `BpAddRequest.via_debugger` (HW bps routed
  to `IDebugControl4::AddBreakpoint2` instead of the driver — the
  debug-port mirror path). Fixed a latent mask/class bug: proto
  kinds_mask bits are now translated to driver `SUSPEX_EVT_CLASS_*`
  bits explicitly (they diverged at BP_HIT). Poll filters post-drain
  on the kind bit; a BP-class request auto-subscribes the driver with
  the consent flag.
- **Agent: DbgEng monitor mode** — `Debug.Attach(monitor=true)` keeps
  the debugee running: the engine loop auto-continues **every** event
  (bp hits and foreign `0x80000004` single-steps `GO_HANDLED` — with
  `EFLAGS.RF` set on the latter so a stray armed DR can't refire;
  other exceptions `GO_NOT_HANDLED`; informational events `GO`), so
  passive observation can never leave the debugee stopped at an
  un-continued event — which is what froze the first test (a
  thread/module event parked the debugee and the driver's synchronous
  ctx op then wedged the sequential ioctl queue). `DebugEvent` records
  now carry the resolved breakpoint address (was: TEB) and the pid;
  attach on an already-active session to the same pid upgrades to
  monitor (resuming a stopped target) instead of failing.
- **Agent: `EnsureStopped`/`ResumeAfterInterrupt`** — dbgeng rejects
  bp ops and discards command output on a running target
  (`E_UNEXPECTED`), and `SetInterrupt` proved unreliable (its "next
  suspension point" never arrives on a quiet debugee). The agent now
  stops a running target with `DebugBreakProcess` (injected int3 —
  deterministic), performs the bp op/command, then resumes with the
  right status for the event it interrupted. `BpAdd`/`BpRemove`/
  `BpSetEnabled` use it unconditionally; `Execute` uses it in monitor
  mode. `injectedBreaks_` tracks our int3s so the monitor pump
  swallows a late-arriving injected break instead of passing it
  NOT_HANDLED (which would kill the process).
- **Orchestrator** — `bp_manage(action='events', mode='auto'|'kernel'|
  'debug_port', dangerous_ok=…, since_seq=…, limit=…)`: kernel mode
  returns `hits[]` (rip/dr6/bp_id/slot/access/irql/pid/tid +
  best-effort kernel-module attribution), `last_seq`, `dropped`,
  `hook_installed`. On `STATUS_NOT_SUPPORTED` (or `mode='debug_port'`)
  it bridges the DbgEng path: attaches monitor-mode to the bp's pid,
  mirrors driver bps through `bp_add(via_debugger=True)` (direct
  `AddBreakpoint2` — no `dbg_cmd('ba …')` interrupt cycle), drains
  `debug_manage(action='events')`, and reports `delivery:
  'debug_port'` + `pump_alive`. `event_manage subscribe` accepts bit
  6 behind `dangerous_ok`; stats expose `bp_hook`/`bp_missed`. Gates:
  `security.allow_event_stream` plus explicit `dangerous_ok`
  (PatchGuard-sensitive, lab-only); new error kinds `bp_hook_failed`,
  `bp_bridge_arm`, `bp_bridge_attach`, `bp_bridge_multi_pid`. The
  debug/event pump now logs exceptions instead of swallowing them and
  self-heals (restarts) when `pump_alive` reports dead.

**Rebuild recipe:** `scripts/build.ps1 -Target all -Configuration
Release`, then
`orchestrator/.venv/Scripts/python.exe scripts/update_target.py
--component all`. The driver swap needs the unload→stage→load path; if
unload refuses (hook live, callbacks registered) reboot the target —
the staged `.sys` activates on boot.

## v0.22 — MCP discoverability, chunked `handles`, `symbols_manage`, scan coverage (orchestrator only; no driver/agent/ABI changes)

External-review pass over the MCP surface: flat action-verb
discoverability, `handles` reliability under load, physical-scan
coverage, and a first-class symbol/PDB tool. All orchestrator-side;
the kernel HW-BP hit ring is the deferred driver/proto phase and is
NOT in this version.

- **Wire-visible action enums + `actions` verb + `tool_index`** —
  every action-dispatch tool's live inputSchema now carries
  `properties.action.enum` (the `*Args` Field descriptions never
  reached the wire; enum metadata goes through
  `Annotated[str, Field(json_schema_extra={'enum': …})]`).
  `ida_manage` intentionally stays enum-free (it passthroughs
  arbitrary shim tool names). Every dispatch tool answers
  `action='actions'` — pure-compute, no client needed — returning
  `{verb: {one_liner, key_args, example}}`, and unknown-action errors
  keep `kind: 'unknown'` while hinting at `actions`/`tool_index`.
  `target_manage(action='tool_index')` dumps the live FastMCP
  registry: tool name, one-liner, and action list per tool.
- **`mem_rw(action='handles')` chunked pull** — the single giant
  `HandleList` reply died mid-stream under load on big tables (pid=4).
  The orchestrator now pages `handle_list(limit=2000, offset=…)`:
  bounded calls fetch only the requested window plus a one-row probe,
  so `item_total` is honestly `null` (unknown) instead of fabricated,
  while `filter`/`summary` still pull the full table. Responses carry
  `pages_fetched`; stream-close mid-pull classifies as the new
  `handles_stream_closed` kind (`agent_stream_closed` for other RPCs)
  with a cheap-shape retry hint. True resume-cookie paging remains an
  agent/proto follow-up.
- **`symbols_manage` (new tool, 18th)** — orchestrator-local PDB
  surface, no target contact unless `view=` asks for a live module
  base. `info` (RSDS name/GUID/age), `ensure` (cache-first MSDL
  fetch; `download=false` checks the cache), `resolve`
  (names→RVA, +VA with `base=`/`view=`; `symbol='mod!Name'` accepted),
  `lookup` (RVA/VA→nearest symbol + displacement via `SymFromAddrW`),
  `layout` (member walk via `SymGetTypeFromNameW`/`SymGetTypeInfo` —
  offsets, sizes, nested UDTs, bitfields; public MSDL PDBs carry
  kernel types), and the IDA-dumped cache family `struct_info` /
  `resolve_member` / `enum_info` / `layouts`. `module=` resolves
  under `artifacts/dumps`+`artifacts/ingested`; `path=` pins an exact
  image. DbgHelp is process-global — all calls serialize on one lock
  and run via `asyncio.to_thread` so MSDL fetches don't stall the
  loop. New kinds: `symbol_not_found`, `dbghelp_failed`,
  `pdb_download_failed`, `invalid_layout`, `offset_out_of_range`.
- **`mem_rw resolve` symbol syntax** — `value='ntoskrnl.exe!
  PsLoadedModuleList(+addend)'` resolves the RVA from a local/dumped
  image's PDB and adds the live module base. Numeric `value=` lookups
  that land in a module now get a best-effort `symbol`/`symbol_rva`/
  `symbol_disp` decoration when a local image is resolvable.
- **`mem_rw read` named-type decode** — `decode={'type':'_EPROCESS',
  'module':'ntoskrnl.exe', 'build_id':…}` decodes a buffer against a
  real type layout instead of primitive tokens. `build_id` (or
  `source='cache'`) reads the dump_layout JSON; otherwise dbghelp
  resolves it from the image's own PDB (`source='dbghelp'`), with
  automatic fallback between the two in `auto`. Members decode to a
  `{name: value}` dict — primitives as ints/floats, `T*` as u64
  pointers, `T[n]` as lists, nested UDTs as nested dicts, bitfields
  shift-masked, unresolvable UDTs as hex blobs flagged `opaque`.
  Short buffers keep the `truncated` contract, never raise.
- **Physical/kernel scan coverage map** — `pattern_scan` (and
  `scan_start` jobs) telemetry now carries `coverage`: merged
  `scanned`/`skipped`/`unscanned` span lists that partition the
  requested range, with per-kind range counts and a `truncated` cap
  flag. Section-scoped scans merge per-span coverage. A hole is now
  distinguishable as 'unreadable' vs 'never reached'.
- **Deferred (next phase, needs driver+proto)**: kernel HW-BP hit
  ring — driver queues DR6/context records, agent drains via a new
  RPC, `bp_manage(action='events')` polls. ETW collection remains
  roadmap (query-only `etw_providers`/`etw_sessions` are as designed).

## v0.21 — gadget scanning + ROP chain validation (orchestrator only; no driver/agent/ABI changes)

rp++-style ROP gadget enumeration and Unicorn-backed validation as three
new `bin_manage` actions, all orchestrator-side behind the existing
`codegen` extra (capstone; `gadget_check`/`chain_check` also need
unicorn). Works on artifacts **and** live module images — for
`source='memory'` every gadget row carries the real KASLR-resolved VA,
so chain entries are usable as-is.

- **`bin_manage(action='gadgets')`** — terminator-anchored backward-decode
  scan over the executable regions (PE section exec flags; raw blobs scan
  whole). Filters: `ending=` (`ret|ret_imm|retf|jmp_reg|jmp_mem|call_reg|
  call_mem|syscall|sysenter|int|all`, with `ret`/`jmp`/`call` expanding to
  their variants), `category=` (load / push / push_ret / mov / mov_imm /
  xchg / mem_xchg / arith / shift / mem_load / mem_store / string /
  stack_pivot / stack_adjust / privileged / trivial / dispatch tags),
  `reg=`, `bad_bytes=` (drops gadgets whose packed VA carries any listed
  byte — the constraint an input channel imposes), `max_len=`, `unique=`
  (`aliases` counts repeats), plus the standard limit/offset/filter/
  fields/summary paging. Every row: `va`, `bytes`, `text`, `insns`,
  `ending`, `categories`, `regs`, `n_insns`, `ret_imm`, `stack_delta`
  (net rsp change where fully understood, else null). Index is cached
  per `(sha256, base VA)` (`cached:` flag; `refresh=true` rebuilds);
  `scan_budget=` bounds the decode attempts and `truncated:` reports
  exhaustion honestly.
- **`bin_manage(action='gadget_check', target=…)`** — execute one gadget
  on a private Unicorn CPU: verdict (`returns|fault:read/write/fetch|
  diverged|cap`), disassembly, register diff, `rsp_delta`, memory writes,
  unmapped/protection faults (classified via `kind: unmapped|prot`),
  `insns_executed`. GPRs are seeded into a sentinel-filled scratch region
  and the synthetic stack is a sentinel ret-sled, so pointer-chasing and
  pivot gadgets complete deterministically instead of faulting on
  garbage.
- **`bin_manage(action='chain_check', chain=[…])`** — execute a candidate
  chain: raw qwords (gadget VAs + data values interleaved, like the
  exploit script) laid on the synthetic stack; `chain=` accepts a JSON
  list, `[0x…, "0x…"]` (bare hex literals tolerated), or csv. Response:
  verdict (`completed|fault:<access>|cap|broke_at:<va>`), `consumed`
  (chain qwords the stack pointer advanced past, null when a pivot moved
  rsp off-chain), `trace` (which chain entries actually executed, in
  order), `final_regs`, `mem_writes`, `non_exec_entries` warnings, and
  `expected_mismatch` against `expected_json=
  {"regs":{"rax":"0x…"},"rsp_delta":N}`. Honest scope note on every
  response: mechanical execution only — syscall/sysenter and API effects
  are not emulated.
- **Live-base fix in `ImageView`** — `ImageView(img, base_va=…)` now
  overrides the header's preferred ImageBase, with reads / names /
  pdata shifted by the delta (default behavior unchanged). All engine
  actions (`funcs`, `cfg`, `xrefs`, …) on `source='memory'` now emit
  *live* KASLR-resolved VAs instead of linker-base ones — previously
  only `exports` patched this up per-action.
- **Kernel-VA emulation via 52-bit relocation** — unicorn 2.1.x only
  *executes* guest VAs ≤ 52 bits (TCG masks every guest access; the
  memory API and register file keep full 64-bit values), so kernel VAs
  (`0xFFFFF8…`) used to fault at entry with a truncated fault address.
  `rop_emu` now maps image regions at `va & (2^52-1)`; code,
  RIP-relative and absolute references stay consistent because the CPU
  masks them identically, while RIP/registers/stack keep full 64-bit
  precision. Code hooks report full VAs; write/fault hook addresses are
  un-masked back (range map + known chain/gadget VAs) for reporting.
  `gadget_check`/`chain_check` therefore work on live kernel modules
  and kernel dumps; responses carry a relocation note when active.
- **`bin_manage source='memory'` partial-read salvage** — the driver's
  PARTIAL walk stops at the first page `MmCopyMemory` refuses and
  completes the IOCTL with `STATUS_PARTIAL_COPY`, which user mode sees
  as a *failed* `DeviceIoControl` (`gle=299`) **with the partial bytes
  dropped** by the I/O manager — so one big read could never salvage a
  module with paged-out pages (`mem_rw read partial=true` and
  `bin_manage source='memory'` both failed hard). The loader now
  re-reads in 1 MiB chunks and bisects failures down to a page, keeping
  every resident page and zero-filling the refused ones (the same
  policy `file_manage dump_module` applies to discarded sections).
  Responses carry `salvage: {holes: [{va, offset, size}…],
  bytes_missing, note}` on `gadgets`/`funcs` so "no gadgets here" is
  distinguishable from "no data here". The clean path is untouched —
  one IOCTL, no bisecting.
- **Driver v1.3 (`SUSPEX_DRV_VERSION_MINOR` 3, ABI stays 10)** —
  `SuspxHandleMemRead` now completes any read that produced bytes with
  `STATUS_SUCCESS` + short `*Done` instead of the warning NTSTATUS
  `STATUS_PARTIAL_COPY` (0x8000000D), which failed the usermode
  `DeviceIoControl` outright (`gle=299`) and dropped the prefix. This
  covers the kernel PARTIAL walk, `MmCopyVirtualMemory`'s inherent
  prefix-partial user reads, and the per-page phys loop — `got<len`
  remains the partial signal through `comm.MemRead` and the agent's
  `first_bad_offset`. The orchestrator salvage path handles both driver
  behaviors (prefix reads on v1.3+, gle=299 bisection on older).
  Deployed to the lab target; verified via `mem_rw read partial=true`
  over a paged-out WMILIB tail (`read_bytes=0x1000`,
  `first_bad_offset=0x1000` instead of gle=299) and a full
  `bin_manage gadgets source='memory'` scan reporting the hole under
  `salvage`.
- New modules `suspex/analysis/rop.py` (scanner/classifier/index) and
  `suspex/analysis/rop_emu.py` (validators); `_UnicornEngine` gained a
  raw `uc_hook`/`uc_hook_del` passthrough for the mem-write /
  unmapped+prot fault hooks. Tests: `tests/test_rop_scan.py` (29),
  `tests/test_rop_emu.py` (20, incl. kernel-VA regression cases),
  `tests/test_bin_memory_salvage.py` (8 — both driver behaviors), plus
  tool-level coverage in `tests/test_bin_manage.py`. Suite: 1079 passed.

## v0.20 — agent primitives round: hands, eyes, ears (driver + agent + orchestrator; ABI v10 wire structs / proto v11)

Turns the stack into an agent's operational hands, eyes, and ears —
direct primitives over verdicts. **Driver + agent rebuild + redeploy
required** (new IOCTLs 0x8A0–0x8A5, new gRPC services Device/Telemetry/
Events, Memory.ThreadList/ObjEnum). Orchestrator is hot-reloadable.

### Trust fixes (Phase A — orchestrator/plugins only)

- `callback_scan` — `_fn_from_block` was sync but called async
  `Reader.u64` (returned unawaited coroutines); now async, and the
  `EX_CALLBACK_ROUTINE_BLOCK.Function` offset corrected to **+0x08**
  (the old `+0x10` read Context).
- `watchdog_manage` arm/list iterated the wrapper dict instead of
  `entries` → AttributeError; both call sites fixed.
- `generate_report` hint pointed at a nonexistent action;
  `knowledge_manage(action='export_json')` implemented for real.
- Plugins wrote to `Path.cwd()/artifacts/`; `artifacts_dir` now flows
  config → runner → SDK → all six plugins.
- `_patterns.yaml` 26200 RVAs corrected against live reads
  (MmLastUnloadedDriver @ `0xef5488`, MmUnloadedDrivers @ `0xef5490`).
- `_require_driver` coverage: one head guard in `mem_rw` (kernel view)
  replaces the scattered per-action checks; hw-BP path in `bp_manage`
  guarded too.
- `driver_trace_scan` test fixture: entries were 0x70 bytes vs the
  scanner's 0x80 window — fixture fixed, 5/5 green.
- `Reader.wstr/cstr` settle on ANY read failure (the agent raises bare
  `RuntimeError` for driver faults, not `SuspexError`) — pool walks no
  longer crash on the last page-crossing entry; `pidddb_scan`'s array
  walk batched into one atomic read (pool-churn race).

### Hands (Phase B1) — `device_manage ioctl`

Usermode agent-side `DeviceIoControl` send primitive: NtCreateFile on
`\\.\X` or raw `\Device\X`, bounded in/out (4 MiB caps), OVERLAPPED +
event wait with CancelIoEx on timeout, no retry (a second send of a
non-idempotent IOCTL is a new side effect). Response carries
`out_hex`/`bytes_returned`/`last_error` (Win32 gle). Gated behind
`security.allow_ioctl_send` (default **false**) + the destructive gate.

### Eyes (Phase B3 + C2)

- `mem_rw threads` — system-wide per-thread inventory. Agent-side base
  path (`NtQuerySystemInformation(SystemProcessInformation)`) works
  without the driver; `kernel=true` routes to the driver-backed walk
  (ABI v11) adding `win32_start_va` + `teb` per row via documented
  ZwQueryInformationThread info classes — no ETHREAD offsets. The
  orchestrator joins start VAs against the module list into
  `in_module`/`module` — the injected-thread *sense*, not a verdict.
- `mem_rw obj_enum` — kernel object-directory enumeration
  (`\Device`, `\Driver`, `\FileSystem`, `\BaseNamedObjects`,
  `\Callback`, `\ObjectTypes`) via `ZwOpenDirectoryObject` +
  `ZwQueryDirectoryObject` — version-proof, no `_OBJECT_DIRECTORY`
  layout assumptions. Depth cap 2, entry cap 4096, `truncated` flag;
  a failing subdirectory is skipped (a hole is not evidence).
  Device names feed `device_manage(action='ioctl')` directly.

### Ears (Phase C1) — `event_manage`

Driver registers `PsSet{CreateProcess,CreateThread,LoadImage}NotifyRoutine`
(subscribe = kernel-visible state, gated like driver_load) and rings
fixed-size events into a bounded 1024-slot overwrite-oldest ring
(callbacks only take a spinlock and copy — process creation is never
stalled). The agent drains via `Events.Stream` (server-streaming,
Watch-template: auth, bounded, cancel-aware) or one-shot `Events.Poll`;
the orchestrator holds the stream in a background consumer and re-serves
via `event_manage` subscribe/poll/unsubscribe/list/stats. Events carry
monotonic per-boot `seq`, `ts_ms`, kind, pid/parent_pid/tid, image path,
per-event `dropped`; the cumulative driver `dropped` counter + `gap`
flag report loss honestly (never claims observation across a
disconnect or overflow). Kernel module loads surface as image_load
events for free. Auto-unsubscribe on view disconnect; per-event records
never touch the knowledge ledger. `Events.Disable` unregisters the
kernel callbacks when the last subscription goes away.

### Telemetry (Phase B2)

`device_manage etw_providers` / `etw_sessions` — read-only ETW
inventory (TdhEnumerateProviders / QueryAllTraces): what telemetry
exists and who is watching. Query-only; starting sessions is out of
scope.

### ABI v10 wire structs (driver + agent rebuild)

New IOCTLs `0x8A0`–`0x8A5` (NOTIFY_SUBSCRIBE/READ/DISABLE/STATS,
OBJ_ENUM, THREAD_LIST) in `comm/suspex_abi.h`
(`SUSPEX_ABI_VERSION 10`, driver 1.2). No changes to existing structs —
old agents pair fine with the new driver. Notify callbacks are
unregistered and in-flight drained on unload (same discipline as the
BP thread-notify path).

**Rebuild recipe:** `scripts/build.ps1` → `scripts/sign_driver.ps1`
(test-sign; import `Suspex0TestSigning.cer` into the target's
`LocalMachine\Root`, TESTSIGNING ON) → `scripts/update_target.py
--component all` → driver_unload/driver_load.

### Crash post-mortem (first notify deployment)

The first Ex-process-notify callback was written with a two-parameter
signature; `PsSetCreateProcessNotifyRoutineEx` passes three
`(PEPROCESS, HANDLE ProcessId, PS_CREATE_NOTIFY_INFO*)` — the OS's
ProcessId landed where the callback read CreateInfo, and the first
process event dereferenced a HANDLE as a pointer → bugcheck. The
runtime-resolved registration (untyped PVOID fn pointer) is why the
compiler could not catch it. Fixed + signature documented in Notify.c.

## v0.19 — knife-derived static-analysis layer (orchestrator only; no driver/agent/ABI changes)

Borrows knife's function-aware analysis engine pattern as an
orchestrator-side layer (`suspex/analysis/`) that works on dumped
modules, spilled artifacts, and — for the byte-surface actions — live
memory ranges. Nothing here needs IDA.

- **New MCP tool `bin_manage`** (read-only). Sources: artifact `path=` /
  `sha256=` (sandboxed to artifacts_dir, spill-resolved) or
  `source="memory"` (`module=`+`kernel=true`, or `address`+`size`).
  - Parse: `info`, `sections`, `imports`, `exports`, `hashes`,
    `imphash`, `sec` (verifies load-config *data*, not just header flags:
    DYNAMIC_BASE without `.reloc`, GUARD_CF without a function table →
    "partial"), `caps`.
  - Byte surface (any buffer): `strings` (ASCII+UTF-16LE), `iocs`
    (URLs/IPs/domains/wallets/regkeys/paths, defanged), `entropy`,
    `scan` (crypto-constant catalog, packer markers, bounds-checked
    embedded-PE detection).
  - Engine (requires the `codegen` extra): recursive-descent function
    recovery seeded from entry/exports/.pdata — `funcs`, `disasm_func`
    (labeled, thunk-resolved), `cfg`, `xrefs`, `paths` (BFS call chains),
    `callgraph`. `jmp [rip+x]` thunks resolve to `dll!api` names; x64
    offset-table switch idioms are recovered (≤4096 entries).
  - Driver passes: `irp_surface` (DriverObject register-copy tracking
    through DriverEntry → MajorFunction[28] + FastIoDispatch table,
    `\\Device\\` name xrefs + IoCreateDevice correlation, kernel-primitive
    call sites) and `ioctl_surface` (`cmp imm32` harvest inside dispatch
    handlers, decoded via ioctl_decode; METHOD_NEITHER flagged).
  - `audit`: bounded backward arg-provenance walk over a dangerous-sink
    catalog → copy-underflow / unbounded-copy / format-string /
    alloc-overflow / exec-injection findings with origin sets + trails.
  - `diff`: normalized per-function body-hash comparison vs
    `compare_path`.
  - `pseudo`: v1-lite flattened pseudocode (per-block const-prop, call
    args from Win64 arg regs, string labels — no structured control flow).
- **`value_manage ioctl_decode / ioctl_encode`** — CTL_CODE field
  split/join with FILE_DEVICE_*/METHOD_*/FILE_*_ACCESS naming, vendor-
  range and METHOD_NEITHER warnings.
- **`mem_rw strings / iocs / entropy`** — the same extractors over live
  ranges (`address`+`size`); `entropy` with `pid=` and no address sweeps
  executable VAD regions (bounded 4 KiB sample each).
- **New plugins:** `irp_hook_check` (live DRIVER_OBJECT MajorFunction[]/
  FastIoDispatch vs the static `irp_surface` expectation — verdicts
  `matched` / `patched_inside` / `redirected_out` / `unresolved_*`) and
  `code_integrity` (live module image vs disk baseline via body-hash diff —
  the inline-patch class `iat_diff` can't see).
- **Shared reachability vocabulary** (`analysis/reachability.py`):
  `ConfirmedDirect / ConfirmedIndirect / Unresolved / NotObserved` — no
  pass ever claims "unreachable".
- **New error kinds:** `bad_magic`, `module_not_found`, `enum_failed`,
  `func_not_found` (registered in `error_maps.KNOWN_KINDS`).
- Every action files a knowledge breadcrumb (`bin_manage:<action>`
  origin) so `knowledge_manage about` surfaces prior analysis.

## Unreleased (2026-09-17) — modular split of oversized files (all builds affected)

- **21 code files >600 lines split into per-domain modules / TUs.** Pure
  refactor: mechanical moves only, no logic changes, no ABI changes,
  no public-symbol renames. Every existing import/include path stays
  live via a facade at the original path.
- **Orchestrator (Python):** `mcp/tools.py` (6227) → `mcp/tools/`
  package with per-tool modules; `mcp/conversions.py` (1602) →
  `mcp/conversions/` (10 modules); `mcp/_envelope.py` (1028) →
  `mcp/_envelope/` (5 modules); `agent_client.py` (1430) →
  `agent_client/` with mixin composition; `findings.py` (1039) →
  `findings/` with mixin composition; `emulate.py` (784) → `emulate/`
  per engine; `sdk.py` (760) → `sdk/` with per-API modules;
  `ida_bridge.py` (1593) → `ida_bridge/` with mixin composition;
  `idalib_stdio_shim.py` (1562) and `suspex_idalib_ext.py` (1217) →
  their respective packages; `scripts/migrate_findings_v2.py` (749)
  → package; `tests/test_multi_agent.py` (656) → per-domain test
  modules.
- **Agent (C++):** `services.cpp` (2037) → 5 TUs; `services2.cpp`
  (709) → 2 TUs; `dbg_session.cpp` (847) → 6 TUs; `host_info.cpp`
  (763) → partial (OS extracted, kernel/security probes remain).
- **Driver (C):** `Dispatcher.c` (930) → per-IOCTL-family files;
  `Breakpoints.c` (681) → sw/hw/list. Declarations moved into
  `SuspexDriver.h`.
- **Comm (C++):** `suspex_comm.cpp` (756) → per-domain files
  (core/mem/ctx/bp/watchdog).
- **Tools (C++):** `drv_exerciser.cpp` (979) → per-command modules.
- **Guardrails added:** [tools/check_line_count.py](tools/check_line_count.py)
  fails if any code file exceeds 600 lines (excepting a small
  documented allowlist). Wired into `.pre-commit-config.yaml`.
- **Allowlisted exceptions** (each documented in the checker):
  `comm/suspex_abi.h` and `proto/suspex.proto` (shared ABI/wire
  contracts consumed by every subsystem — splitting touches every
  consumer); `mcp/tools/{common,target,mem}.py` (single tool functions
  or shared helper module that can't split without changing tool
  architecture); `agent/src/grpc/services_memory.cpp`,
  `agent/src/host/host_info.cpp`, `mcp/tools/ida_bridge/openclose.py`
  (Phase-6/4 follow-ups tracked separately).
- **Verification:** orchestrator pytest **919 passed** (matches
  pre-split baseline). C++/WDK builds not yet re-run in this pass —
  build after pulling and re-run `cmake --preset win64-user`.

## v0.18.0 (2026-09-17) — knowledge_manage: shared cross-agent KB (orchestrator rebuild only)

- **`findings_manage` → `knowledge_manage`** — the tool grew past its
  original scope (was per-agent finding log + human report). It now
  holds: findings, low-ceremony notes, an artifact index keyed by
  sha256 with per-alias/per-version tracking, tool-event breadcrumbs
  auto-emitted by `file_manage dump_module` / `ida_manage open|*` /
  `mem_rw pattern_scan` / `script_manage run` / `parity`, IDA-session
  records (which `.i64` exists for which sha, live/closed), and FTS5
  full-text search over findings + notes + evidence. The old tool name
  `findings_manage` stays available for one release as a deprecation
  alias that logs a warning on first use.
- **`about(artifact_sha=…|alias=…|module=…|address=…|target=…)`** —
  primary "check first, don't re-derive" API. Returns
  `{artifacts, findings, notes, events, ida_sessions}` filtered by any
  subset of scoping keys. `list` defaults to global scope (all
  sessions) now; pass `session_id` to filter.
- **Additive schema migration** — every ALTER TABLE / CREATE TABLE
  runs idempotently on first open; existing DBs upgrade in place with
  no data loss. Old code paths reading the pre-v0.18 shape still work.
- **On-boot backfill fallback** — an empty artifacts table triggers a
  one-shot walk of `artifacts_dir/<sha>/<name>` to seed the artifact
  index cheaply, so a fresh install that hasn't run the migration
  script isn't completely blind on day one.
- **`scripts/migrate_findings_v2.py`** — one-shot CLI (not run on
  boot) that consolidates every pre-v0.18 knowledge source: merges
  both legacy DBs with dedup, parses the free-form `refs` field for
  file paths / prior-finding IDs / sha256 mentions and back-fills the
  new structured columns, walks the artifacts dir for every friendly-
  name IDA workdir (empty ones become `historical_ida_workdir` notes
  so `about(alias=…)` still returns something), and **copies +
  registers historical `.i64` databases** from `temp_spoofer/` (and
  `artifacts/temp_spoofer/`) into the canonical
  `artifacts/<sha>/<name>.i64` layout with a `historical_ida_i64`
  note carrying the exact reopen command. `--dry-run` prints planned
  inserts; `--commit` writes a NEW `findings_v2.db` — never mutates
  legacy DBs. Conflicts and unmatched refs land in
  `artifacts/_migration/*.jsonl`. Real repo dry-run: 293→291 findings,
  189 evidence rows preserved, 4 .i64 databases copied, 3 parity
  snapshots imported, 8 artifacts, validation aliases (`nvlddmkm.sys`,
  `disk.sys`, `ntoskrnl.exe`, `usbhub.sys`, `Ntfs.sys`, `tcpip.sys`)
  all resolve to non-empty `about()` results.
- **`ArtifactsConfig.findings_db`** — new absolute-path config field.
  Empty inherits `<dir>/findings.db` (relative to cwd — the pre-v0.18
  behaviour that caused two DBs to accumulate under different launch
  cwds). Set an absolute path to pin regardless of launch dir.
- **New SKILL.md ground rules** — "Check first, don't re-derive"
  (call `about()` before opening IDA / deep recon) and "Leave the IDA
  database more readable than you found it" (renames/comments persist
  in the .i64 and are auto-logged so the next agent inherits the
  work). Two new recipes: **Compare two versions of a driver**
  (`artifacts(alias='nvlddmkm.sys')`) and **Co-attach a peer's IDA
  session** (pass `name=<peer's session>` to inherit their renames
  live).
- **Removed MCP action**: `generate_report`. Returns
  `{ok:false, kind:'removed_action'}` with a hint pointing at `list`
  / `about` / `export_json`. The `FindingsLedger.generate_report`
  Python method stays for one release for external scripts.
- **Breadcrumb attribution**: findings, evidence, notes and events
  all carry `agent_id` (populated from `current_client_id()`), so
  `about()` responses tell you which agent contributed what.
- **Dedupe on write**: `knowledge_manage(action='record', ...)`
  refuses to insert a second open finding with the same
  `(title, artifact_sha, address)` signature — returns
  `duplicate_of=<existing>` with a hint to `add_evidence` instead.
  Pass `dedupe=false` to force.
- **Blast radius**: orchestrator-only, no ABI bump, no agent /
  umagent / driver rebuild. Hot-reload the orchestrator and every
  existing agent picks up the new API on next call.

## v0.17.1 (2026-09-16) — value_manage rename + arithmetic expansion (orchestrator rebuild only)

- **value_manage (renames type_convert)** — the pure-compute
  cast/encode/hash tool becomes value_manage since it operates on
  values, not types; the actual type surface now lives in ida_manage
  (type_info / struct_info / resolve_offset per v0.17 C2). type_convert
  is removed in the same release (no deprecation window) — every caller
  updates to value_manage at the v0.17.0 → v0.17.1 boundary. The
  underlying pure primitives in `orchestrator/src/suspex/mcp/conversions.py`
  and the extracted per-action dispatcher in `value_ops.py` stay stable,
  so the migration is a name change on the MCP surface only.
- **value_manage(action="eval")** — safe expression evaluator over
  AST-whitelisted grammar for programmer arithmetic classes LLMs mis-
  compute in-context: mixed-radix arithmetic, 64-bit bit ops
  (popcount / ctz / byteswap / rotl / rotr / sign_extend), range
  checks (in_range), alignment (align_up / align_down). No eval(),
  no attribute access, no imports, no comprehensions — every non-
  whitelisted node fails with kind="unsupported_op". Named constants
  for common addresses (KUSER_SHARED_DATA, PAGE_SIZE, masks, etc.)
  resolvable inline; enumerable via action="constants".
- **New reserved error slugs:** bad_expr, unsupported_op,
  undefined_name, expr_overflow, division_by_zero,
  evaluation_timeout.
- **SKILL.md ground rules (two of them):** agents integrating
  suspex0 (Devin, Kilo, Claude, etc.) are now instructed under a
  "Ground rules" section to (1) delegate every arithmetic / bit op /
  address offset / range check / cast / encode / hash / err_lookup
  to value_manage instead of computing in their head, and (2) never
  hand-decode PE / structured binary from raw bytes — dump the
  module with file_manage and open it in IDA (ida_manage) for real
  parsers, real xrefs, and a real name table. Same discipline
  applies to kernel structs via mem_rw(action='read', decode=...)
  and mem_rw(action='walk_list', struct=...). The first rule is
  mirrored into the value_manage docstring; the second is mirrored
  into the ida_manage and mem_rw docstrings so schema-inspecting
  integrations see both.

## v0.17.0 (2026-09-16) — Orchestrator + IDA ergonomics (orchestrator rebuild only)

Six-package parallel cycle: envelope + context economy (A), IDA session
lifecycle (C1), IDA introspection (C2), decompile & xrefs (D), watchdog
+ audit + contention (E), error classifier subset (F-1 + F-2), mem_rw
uplift (B). Driver ABI and agent binaries are unchanged from v0.16.1 —
only `orchestrator/` rebuilds. 789 orchestrator tests pass.

**Scope note:** worker G's driver v1.3 package (G-1 removal of
`SUSPEX_MEM_FLAG_ALLOW_SOFTFAULT`, G-2a KUSER short-circuit, G-2b
`SuspxProbeVaEx`, G-2c `SUSPEX_PROBE_VA_EX` IOCTL, G-2d Status IOCTL
version + build fields) is coded on `feat/v0.17-g-driver-v1.3` (commits
`51d56cc` / `d877196` / `e3b248b`, ABI v10, 15/15 orchestrator-side
regression tests pass) but not merged into this stanza — the signed
`.sys` build requires a WDK-provisioned host, so the whole G cycle plus
worker F's `probe_va` validator tag (F-3a) and dynamic driver-version
hint substitution (F-3b) — which both consume the new driver — move to
**v0.17.1**. The `cp2-driver-v1.3` coordination point was removed from
the v0.17 board. `orchestrator/tests/perf_baseline.py` scaffolding
(H-2) is also carried into v0.17.1.

- **D-4 · `nearest_function` on decompile failure envelopes** —
  when ``decompile_function`` fails (mid-function address, no Hex-Rays,
  corrupted analysis) the shim's fallback used to return just
  ``status:'fallback_disasm'`` + ``decompile_error`` + the fallback
  disassembly. v0.17 D-4 auto-computes
  ``nearest_function:{start, end, delta, name}`` from
  ``ida_query_context`` and (best-effort) ``get_function_by_address``,
  and attaches it to every failure envelope — both the
  fallback-disasm success path and the fallback-also-fails path,
  which now surfaces as ``ok:false, kind:"decompile_failed"`` with
  the enrichment intact. The enrichment is entirely best-effort;
  every failure mode in the enrichment chain returns ``nearest_function
  =null`` rather than cascading a second error onto the caller.
- **D-3 · `decompile_function` windowing + annotations toggle** —
  the vendored ``decompile_function`` unconditionally emitted per-line
  ``/* line: N, address: 0x… */`` trailers — measured at 30-40% wire-
  token overhead across a 35 KB decompilation. v0.17 D-3 flips the
  default (``annotations=false``; opt back in with ``annotations=true``)
  and adds three new knobs on
  ``ida_manage(action="decompile_function", args_json='{...}')``:
  * ``around_address="0x…"`` — return a window centred on the closest
    ea, with ``window_lines`` above and below (default 40).
  * ``window_lines=N`` — window half-width in decompiled lines.
  * ``max_bytes=N`` — truncate the response after N bytes and set
    ``truncated:true``.
  The transformer keys off the raw ``/* address: 0x… */`` hints, so a
  windowed call needs ``annotations=true`` to key on; if the text has
  been de-annotated the window degrades gracefully to the full stripped
  text (``windowed=false``). Response envelope now carries
  ``{text, annotations, windowed, window_span, truncated, byte_count}``.
  Breaking default flip on ``annotations`` vs. v0.16; callers who need
  the ea map back can opt in.
- **D-2 · `analyze_struct_detailed` compact default** —
  the vendored ``analyze_struct_detailed`` unconditionally dumped every
  member — RAID_ADAPTER_EXTENSION at 232 fields / 28 KB of wire tokens
  when the caller wanted one field. v0.17 D-2 lands a shim-side
  transformer that collapses the response to
  ``{name, size, member_count, kind:"summary", first_10:[...]}`` unless
  the caller opts into ``detail=true`` (full list) or names specific
  ``members=["Signature", "Flink"]`` (verbatim projection).
  ``members=[...]`` wins over ``detail`` when both are passed. Shape-
  robust: accepts a raw ``list[dict]`` (older vendored builds) or a
  ``{name|struct_name, size, members}`` dict; missing ``members`` key
  degrades to ``member_count=0`` rather than raising. Breaking default
  flip vs. v0.16; ``detail=true`` restores the historical shape.
- **D-1 · grouped xrefs on `get_xrefs_to`** —
  the vendored ``get_xrefs_to`` returned a flat ``list[Xref]`` with a
  fully nested ``Function`` per xref — 39 xrefs from 30 unique functions
  ballooned to 7.7 KB of duplication on the ARP session. v0.17 D-1
  lands a shim-side transformer (``orchestrator/ida_shim_ergo.py``
  ``group_xrefs``) that groups by containing function, keeps a single
  function header per group, and supports ``fields=[<col>...]``
  projection. Xrefs from data / undefined regions bucket under a
  ``function.start_ea="0x0"`` / ``name="<data>"`` sentinel group so a
  caller sees them without a second call. New knobs on ``ida_manage
  (action=get_xrefs_to, args_json='{"address":"0x…",
  "group_by_function":false}')`` — default is grouped; pass
  ``group_by_function=false`` for the historical flat shape. Breaking
  default flip vs. v0.16; kept the escape hatch for one release.
- **D-6 · decompile type-wobble recipe in SKILL.md** —
  `.devin/skills/suspex0/SKILL.md` grows a `Recipes` section with a
  concrete "fixing decompile type-wobble on kernel structs" flow: pull
  the real WDK layout via `get_struct_member` (or `resolve_offset` for a
  reverse offset), declare the type with `exec_idapython` +
  `ida_typeinf.parse_decls`, retype the misidentified local via
  `set_local_variable_type`, and re-decompile with `annotations:false`.
  Docs only — no code path change.
- **D-5 · `exec_idapython` native structured result** —
  `orchestrator/suspex_idalib_ext.py:exec_idapython` used to return
  `result=repr(<value>)`, forcing every caller who set `result = {...}`
  to `ast.literal_eval` the string on the far side. The response now
  carries the value as native JSON when it round-trips through
  `json.dumps` (dicts stay dicts, lists stay lists, ints stay ints;
  `bytes` and `bytearray` ride the default hook so binary reads land as
  a hex string), and only falls back to a bounded `repr` for genuinely
  unserializable objects (recursive structures, custom types) or when
  the native serialization exceeds the 1 MiB response cap. New fields:
  `result_native` (bool — whether the value round-tripped) and
  `result_type` (Python type name); `result_truncated:true` surfaces the
  bounded-repr fallback. Breaking-shape change vs. v0.16 — callers that
  did `ast.literal_eval(result)` should drop the eval.
- **B-2 · `mem_rw read` `from_va` + `resolve_physical` shortcut** —
  one driver round-trip replaces (va_translate) + (mem_rw read
  space='physical'). `mem_rw(action='read', space='physical',
  from_va=<VA>, size=N)` translates the kernel VA via the driver's
  CR3 walk (`mem_va_translate`) and reads from the resolved PA in the
  same call. Response carries `{va, physical_address, size, hex,
  cr3, page_size_shift, ...}`; composes with `decode=`.
  - A translate fault (VA not mapped, driver raises) surfaces as
    `kind:"pte_absent"` with a hint pointing at `probe_va` for the
    PML4/PDPT/PD/PT layer breakdown; a `present:false` result surfaces
    the same slug and attaches the `translate` dict so the caller can
    inspect the layer that fenced the walk without a second round trip.
  - `address` + `from_va` together is refused with
    `kind:"kwarg_collision"` — they select different code paths and the
    combination is always the caller's mistake.
  - `resolve_physical=true` with a non-physical `space` is refused with
    `kind:"invalid_parameter"`.
- **B-1 · `mem_rw` structured decode + batch + walk_list + wrappers** —
  the biggest converging complaint in the audit (four reports asked for
  it) lands as one package.
  - **B-1a** `mem_rw read` grows `decode=<spec>`. The spec is a list of
    type tokens (`["u64","ptr","cstr"]`) or a shorthand string
    (`"u64[4]"`, `"u32[]"`, `"u32,u32,cstr"`); tokens are u8/i8/u16/i16/
    u32/i32/u64/i64, ptr (x64 u64), f32/f64, cstr (utf-8 NUL-terminated),
    wstr (utf-16-le NUL-terminated), utf8/utf16le (consume the
    remainder). Response gains `values` + `layout` (per-token
    `{offset, type, size}`) plus `remainder_hex` / `truncated` on short
    buffers. `include_ascii=true` re-enables the pre-B-1 ascii preview
    when decode is set. Implementation lives in
    `conversions.decode_buffer` — pure-compute, never raises on short
    buffers.
  - **B-1b** `mem_rw read` grows `reads=[{va, size, decode?}, ...]`
    batch mode. Each row runs independently; a single failed row appears
    as `{address, error}` while the rest of the batch completes.
    Replaces the 3-6 sequential reads every kernel-object walk used to
    issue.
  - **B-1c** new `mem_rw walk_list` action. Follows a linked list from
    `address` hopping `value` bytes into each node to read the next
    pointer. Stops on null Flink, self-loop, or `count` iterations.
    Per-node `decode=` uses the same decode grammar as `read` so the
    walker returns typed values (not raw bytes) at every hop.
  - **B-1d** three thin convenience wrappers on `MEM_ACTIONS`:
    - `read_qwords(address, count)` returns `{values, values_hex,
      layout}`.
    - `read_unicode_string(address)` chases the UNICODE_STRING header
      at `address` (Length:u16, MaxLength:u16, pad:u32, Buffer:ptr)
      and decodes the buffer under utf-16-le.
    - `read_ansi_string(address)` — same shape, decoded under mbcs.
  - **conversions.py** grows `decode_buffer`, `_expand_spec`, and
    `_find_wstr_term` — pure-compute helpers exported from the mem_rw
    call sites so batch/walker rows all share one decoder.
- **B-5 · `mem_rw write` `verify=true`** — atomic write-then-read-back.
  On a matching readback the response gains `verified:true`; on a
  mismatch it carries `verified:false`, `diff_offset`,
  `expected_hex` + `actual_hex` (16-byte windows) and a hint pointing
  at COW / read-only / device-mapped ranges. A readback that itself
  throws surfaces `verified:false, read_back_error:"..."` and a hint
  about write-only / fenced / unmapped page-boundary cases so the
  caller can retry smaller chunks. Payloads larger than 64 KiB attach
  a `warnings:[...]` note (verify doubles bandwidth) via the shared
  `_envelope.warn` slot. verify=false (default) preserves the pre-B-5
  wire shape.
- **B-4 · `mem_rw modules` filter finish-up** — four sub-items:
  - **B-4a** the schema docstring for `filter` no longer claims
    "exact-match"; it now documents the case-insensitive substring
    semantics `_envelope._filter_rows` has shipped since v0.14 and
    points callers at `name_regex` / `name_glob` / `path_contains`
    for typed row filters.
  - **B-4b** three dedicated typed kwargs on the `modules` action —
    `name_regex` (case-insensitive re.search), `name_glob`
    (case-insensitive fnmatch), and `path_contains` (case-insensitive
    substring on the module path). `_apply_modules_filter` at
    `tools.py:340-359` was defined in v0.14 but never invoked; this
    finally wires the call site. A malformed regex returns
    `kind:"invalid_parameter"` with the compile error text quoted
    instead of blowing up with an unhandled `re.error`.
  - **B-4c** zero-match diagnostic — when any typed filter trims the
    module list to empty, the envelope carries `kind:"filter_no_match"`,
    `filter_matched:false`, a 5-item `sample_available_names` snapshot,
    and `total_available` so a caller can spot a KASLR rebase / typo
    in a single round trip.
  - **B-4d** `name=` selects a target view ('kernel'|'user'), never a
    row filter. Callers who pass anything else (a bare module name, a
    substring) hit `kind:"kwarg_collision"` up front with a hint
    pointing at `filter=` / `name_regex=`. Fixes the ARP-report
    complaint that `name=tcpip` silently routed to a non-existent
    view.
- **B-3 · `mem_rw read` `offset` no longer a silent no-op** — the tool
  signature accepted `offset` but the `read` branch at
  `tools.py:2049-2098` never referenced it, so a caller migrating from a
  `base+offset` call convention received the wrong bytes with no
  diagnostic. `read` now refuses non-zero `offset` up front with
  `kind:"unknown_kwarg"` and a hint that spells the intended migration
  path (`address = base + 0x<offset>` before the call). `offset=0` is
  the default and still succeeds. Reserved slug already in
  `error_maps.KNOWN_KINDS` per _shared.md §0.4.
- **A-5 · `warn()` / `warn_if()` envelope helpers** —
  `orchestrator/src/suspex/mcp/_envelope.py` now exposes
  `warn(env, msg)` and `warn_if(env, cond, msg)` so every worker
  appends to `env['warnings']` through the same idempotent, dedup'ing
  helper instead of hand-rolling the list append at the call site.
  Publishes CP-5 (`cp5-warn-helper-live`) so E-1 (bare-arm warn)
  and E-3 (contention warn) can wire against it.
- **A-2 · compact text-line collapse on more list actions** —
  `_envelope.finalize` grows a `(tool, action) → (source_key, transform)`
  table (`COMPACT_TRANSFORMS`). When `verbosity="compact"` matches a
  registered entry, the row list is rewritten in place from
  `list[dict]` to `list[str]` — one row per readable text line — cutting
  wire tokens ~55-70% on a 64-row `disasm` and giving terminal readers
  something scannable. Ships transforms for `mem_rw disasm` (`addr  bytes
  mnemonic op_str [; sym]`), `handles` (`handle=… type=… obj=… path=…`),
  `vad` (`start-end  protect=… type=… commit=…`), `heaps` (`heap=…
  base=… committed=… reserved=… flags=… blocks=N`, source key `heaps`),
  `exports` (`addr  ord=N  name [→ forwarder]`, source key `entries`),
  and `imports` (`iat_slot=… dll!name → resolved (mod) [HOOKED]`).
  Non-registered actions and every non-compact verbosity level are
  untouched.
- **A-4 · `summarize_ops` helper for `recent_ops summary=true`** —
  `orchestrator/src/suspex/mcp/_envelope.py` grows a
  `summarize_ops(rows)` helper that aggregates a `recent_ops` ring
  (the 128-row `{method, elapsed_ms, ok, ts, ...}` buffer) into
  `{method, count, ok_count, err_count, min_ms, max_ms, avg_ms,
  last_ts}` records sorted busiest-first. Agent E wires it at
  `target_manage recent_ops` in a follow-up commit; the helper is
  landed early so E-2's audit writer can share the same aggregation.
- **A-3 · `reg_manage get` `raw_hex=true` opt-in** —
  `AgentClient.reg_get` used to unconditionally emit
  `{type, size, hex, str, qword, multi_sz}` — every rendering, every
  time — even for a REG_SZ or REG_DWORD where three of the four value
  fields carried no signal. The default response now picks one
  canonical rendering per REG_ type: REG_SZ / REG_EXPAND_SZ →
  `value: <str>`, REG_DWORD / REG_QWORD → `value: <int>`, REG_MULTI_SZ
  → `value: [<str>...]`, REG_BINARY / REG_NONE / REG_LINK / unknown →
  `hex: "..."`. Callers that need every rendering (forensic dumps,
  legacy scripts) pass `raw_hex=true` to `reg_manage get`, which
  restores the historical wide shape. `_suspex_driver_probe.py` — the
  only in-tree consumer that reads `str` and `qword` off the same
  response — passes `raw_hex=true` explicitly.
- **A-1 · single-encode MCP tool responses** — before v0.17 every
  `@mcp.tool` reply went out on the wire twice — once as
  `content[0].text` and again as `structuredContent.result` — because
  the tool bodies returned `_j = json.dumps(env, ...)` and FastMCP
  wrapped that string on both slots. `_j` at `tools.py:113-114` now
  routes finalized envelopes through the new
  `_envelope.to_tool_result(env)` helper, handing FastMCP a
  `ToolResult` with `content=[]` and `structured_content=<envelope>`
  so the payload reaches the client once. Legacy dual-emit stays
  available for one release via `SUSPX_MCP_LEGACY_DUAL_CONTENT=1` for
  MCP clients that still ignore `structuredContent`. Ledger evidence
  writes (parity report, yara-match list) and inner `run()` bodies
  that pre-build an envelope-shaped dict keep the historical JSON
  string path — the discriminator is `summary.size_bytes`, which
  only `_envelope.finalize` stamps on the outbound envelope. Ships
  CP-1 (`cp1-envelope-ready`) alongside A-5.
- **C1-5 · `exec_idapython` alias `code`/`script` → `source`; short
  `struct`/`member` aliases on `get_struct_member`** — added to
  `orchestrator/ida_shim_ergo.py:ARG_ALIASES` so callers who reach for
  the natural short names hit the canonical spelling instead of a
  schema-validation refusal.
- **C1-4 · IDA session continuity across orchestrator restart** —
  the bridge writes a small manifest at every open / close
  (`~/.suspex0/ida_sessions.json` by default, overridable via the
  `SUSPX_IDA_MANIFEST` env var for tests). On startup the
  manifest is loaded name-by-name into an in-memory pre-open
  set; the first session-scoped `ida_manage` call that
  references a pre-restart name silently re-opens the DB
  instead of erroring out with unknown-session. Stale manifest
  entries whose input paths no longer exist are dropped on
  first lazy-open attempt. Corruption, missing files, and
  version drift all fall through to "start fresh" instead of
  blocking bridge construction. Manifest write is atomic
  (tmp+rename) so a concurrent read from a peer orchestrator
  never sees a half-written file.
- **C1-3 · MRU IDA session auto-fill on session-scoped actions** —
  a session-scoped `ida_manage` action (decompile, disasm, xrefs,
  funcs, and every passthrough shim tool) now falls back to the
  most-recently-opened session when the caller didn't supply
  `name=`. The bridge tracks MRU on every successful open / reuse
  and rotates onto any remaining session when the current MRU
  closes (clears when the last session goes). The response
  envelope carries a top-level `warnings:[...]` note that names
  the auto-filled session so silent MRU steering never masks
  which database served the request. When no MRU exists a session-
  scoped call raises with an actionable "call open first" hint
  instead of the historical shim-level "unknown database"
  confusion. `open`, `open_async`, `open_status`, `list`,
  `schemas` never auto-fill (they either create a session, target
  a specific one, or don't need one).
- **C1-2 · `open_status` / `open` envelope carries a
  `symbols`+`named_functions`+`pdb` triple** — every ready-path
  envelope from `ida_manage(open|open_async|open_status)` now
  reports whether symbols actually loaded
  (`loading|loaded|failed|none`), the live function count, and
  whether the PDB matched (`matched|missing|failed|unknown`).
  The pre-v0.17 envelope stopped at `status:ready` so a "PDB fetch
  silently failed" session was indistinguishable from a healthy one
  until a name search came back empty. The classification runs
  server-side against a live `ida_status` probe; wire errors on the
  probe fall through to `unknown` so a hiccup never downgrades a
  ready reply. Pending envelopes emit `symbols:"loading"` +
  `named_functions:0` + `pdb:"unknown"` so the field set is stable
  across the whole open lifecycle. Freezes the shape D-4 needs to
  wire `nearest_function` (cp4-open-envelope-frozen).
- **C1-1 · `ida_manage open` honors the caller-supplied `name` verbatim** —
  `orchestrator/src/suspex/ida_bridge.py`'s `open` / `open_async`
  branches previously dropped the top-level `name` kwarg and derived
  the session id from `Path(path).stem`, so `ida_manage(open,
  path='tcpip.sys', name='tcpip26200')` silently collapsed to
  `tcpip`. New precedence rule: top-level `name` > embedded
  `preferred_session_id` > `Path(path).stem`. Names now validate
  against `^[A-Za-z0-9_.-]{1,64}$` (traversal / whitespace / control
  chars refuse up front) and a same-name-different-path reopen raises
  a `session_exists:` error instead of silently synthesising
  `<name>#<hex>`. Peer collisions across owners still fall through to
  the existing silent `#hex` synth in `_resolve_open_public_name`.
- **C2-1a · `ida_manage(schemas, args_json='{"tools":[…]}')` filter** —
  the schemas action used to always dump every tool with its full
  `inputSchema` (~25 KB — roughly 30% of a session's context in one
  call). Callers can now pass a `tools` list (or a bare string) in
  `args_json` to narrow the response to only the tools they need.
  Full-dump behaviour is preserved when no filter is supplied. The
  response envelope now carries `{count, filtered, tools:[…]}` under
  `data`, replacing the old bare-list payload.
- **C2-1b · `ida_manage(tools)` light inventory** — new action returns
  `{name, one_liner}` for every backend tool. The one-liner is the
  first sentence of the tool's description (hard-capped at 120
  chars), so the discovery call stays cheap enough to run at session
  start. Use it to pick which tool's inputSchema to fetch via the
  filtered `schemas` action.
- **C2-3a · `resolve_offset(struct, offset)` reverse-lookup tool** —
  new IDA-side tool in `orchestrator/suspex_idalib_ext.py`. Given a
  struct name plus a byte offset it returns the containing field, the
  full dotted path (recurses into nested UDTs — e.g.
  `_KTHREAD.Pcb.DirectoryTableBase`), the size, and the offset
  remainder inside that field so a caller decoding
  `base + 0x28` no longer chains `get_struct_member` per hop. Typed
  errors: `struct_not_found` | `not_a_udt` |
  `udt_details_unavailable` | `offset_out_of_range` |
  `invalid_parameter`. Unblocks the `walk_list` struct-decode path
  (CP-3).
- **C2-1c · Narrative descriptions trimmed off the wire** — the
  `get_struct_member`, `type_info`, `dump_layout`, and
  `list_functions_filter` docstrings each had an operational-review
  narrative that added 300-600 bytes to the schemas dump per tool.
  The narrative moved to inline comments (still on the source, off
  the wire) and each docstring shrank to 2-3 actionable lines plus
  the typed error list. Total savings on a full `schemas` dump:
  ~1.5 KB. Combined with C2-1a's `tools=[...]` filter and C2-1b's
  one-liner inventory, the discovery/lookup workflow now avoids
  paying the narrative cost at all.
- **C2-4 · `list_functions_filter(name_filter, offset, count)`** —
  new IDA-side helper that runs a case-insensitive substring
  filter on function names inside the extension so a caller
  reaching for ``"DispatchIoctl"`` on a 15 000-function driver
  no longer has to page through the whole list on the wire.
  Response shape mirrors the vanilla ``list_functions``
  (``functions:[{address, name}]``) and carries a top-level
  ``total_matched`` / ``truncated`` / echoed ``name_filter``
  so a caller can verify pagination without a follow-up call.
  Empty ``name_filter`` is a passthrough of the normal
  ``list_functions`` window.
- **C2-3c · PDB-layout cache — `dump_layout` (IDA-side writer) +
  `suspex.pdb_layout_cache` (orchestrator-side reader)** — analysts
  ask the same `struct.field` layout questions across sessions
  (`_EPROCESS`, `_KTHREAD`, `NL_NEIGHBOR_STATE`) and re-opening
  IDA per lookup is prohibitively slow. The new
  `ida_manage(action="dump_layout", args_json='{"module":
  "ntoskrnl.exe","build_id":"…","types":["_EPROCESS",…]}')` tool
  walks the IDB's named types and writes an atomic JSON cache to
  `~/.suspex0/pdb_layouts/<module>__<build_id>.json`. The new
  `orchestrator/src/suspex/pdb_layout_cache.py` module reads the
  same cache and exposes `struct_info` / `resolve_member` /
  `enum_info` / `list_cached_layouts` — pure-compute helpers that
  return the same envelope shape as the live-session tools
  (`kind:"struct"|"enum"`). Typed errors: `pdb_layout_missing`
  (with `installed_builds` hint so a mismatched build id is
  visible), `type_not_found`, `offset_out_of_range`,
  `invalid_layout`, `invalid_parameter`. Nested UDT recursion
  stops at uncached inner types with a friendly `note` telling
  the caller which type to add to the next dump. Reserved
  error-kind slug (`pdb_layout_missing` — v0.17 registry).
- **C2-3b · `type_info(name)` for structs, unions, typedefs, and
  enums** — new IDA-side tool. Structs return a terse
  `{kind:"struct", size, member_count, first_members[:10]}`
  preview (call `analyze_struct_detailed` for the full dump);
  enums return every `(name, value)` pair so a `NL_NEIGHBOR_STATE`
  or `KWAIT_REASON` lookup no longer needs a hand-rolled
  `exec_idapython` recipe. Typedefs report their expanded string
  form. Walks the modern `ida_typeinf` view first, then falls back
  to the classic `ida_enum` map for enums that pre-date the
  typeinfo migration. Typed errors: `type_not_found` |
  `udt_details_unavailable` | `enum_details_unavailable`.
- **C2-2 · `pattern_scan` + `qword_value_scan` on the IDA side** —
  two new tools in the suspex idalib extension. `pattern_scan(hex,
  seg?, limit?, start_ea?, end_ea?)` walks a segment (or the whole
  IDB when `seg` is empty) matching a byte pattern with `??`
  wildcards, returning `[{ea, function, function_name}]`. Uses a
  hand-rolled masked scanner instead of `ida_bytes.bin_search` so
  it isn't broken by the SWIG overload TypeError seen on IDA >=
  9.0. `qword_value_scan(value, seg?, limit?)` encodes a u64
  little-endian and delegates to `pattern_scan`, replacing the
  hand-rolled `exec_idapython` recipes callers previously wrote
  to find vtable slots / encoded pointers. Typed errors:
  `invalid_parameter` (bad hex, unknown segment, reversed range,
  oversized value).
- **F-1 · net-layer connect classifier + `wait_connectable`** — the
  agent-side pre-flight probe now runs a plain TCP handshake before
  `AgentClient.connect()`, so `WSAECONNREFUSED` / `WSAETIMEDOUT` /
  `WSAEACCES` / `WSAEHOSTUNREACH` / `WSAENETUNREACH` bubble through
  `_error_enrich.HINT_RULES` as the specific slugs
  `connect_refused` / `connect_timeout` / `connect_blocked` /
  `host_unreachable` / `network_unreachable` (each with an actionable
  next step) instead of collapsing to the generic
  `channel_unavailable`. `socket.timeout` maps to `WSAETIMEDOUT` so
  loopback-to-closed-port classifies the same way on Windows and
  POSIX. New action `target_manage(action='wait_connectable',
  name?, host?, port?, timeout_s=15)` polls the same probe + a gRPC
  status roundtrip with bounded exponential backoff (delay caps at
  3 s) until the target is reachable or the deadline expires;
  timeouts return `kind='wait_timeout'` with `attempts`, `elapsed_s`,
  and `last_probe_kind` so callers can branch without re-classifying.

- **F-2 · schema-mismatch classifier + `KNOWN_KINDS` slug registry** —
  pydantic `extra_forbidden` / `Field required` errors used to bubble as
  raw validation-error text; they are now classified as
  `schema_mismatch` / `schema_missing_field` and the hint substitutes
  the calling tool's name so callers see
  `schemas(tools=['mem_rw'])`. `error_maps.KNOWN_KINDS` documents every
  `error.kind` slug the surface is allowed to emit (per _shared.md §0.4)
  and `test_f_2_known_kinds_registry_covers_tools_py` lints tools.py so
  typos like `bad_argment` fail the build. New reserved slugs for the
  v0.17 cycle: `connect_blocked`, `connect_timeout`, `connect_refused`,
  `host_unreachable`, `network_unreachable`, `wait_timeout`,
  `schema_mismatch`, `schema_missing_field`, `pte_absent`,
  `kuser_readable`, `vad_probed`, plus every peer worker's reserved
  slug from §0.4.
- **E-1a · `watchdog_manage(action="auto_kick")` cleanup on driver
  disarm** — the pump no longer leaks a zombie state row when the
  driver disarms the slot out from under the kicker
  (`STATUS_NOT_FOUND`). The pump now stamps `stopped`,
  `stopped_reason`, and `stopped_ts` on its state; `auto_status` reaps
  rows older than 60 s and renders `task_alive` + `stopped` +
  `stopped_reason` so callers can tell a live kicker from one waiting
  to reap.
- **E-1b · `watchdog_manage(action="list")` owner + kicker
  annotations** — every row now carries `owner` (client_id or `null`),
  `foreign` (True when a different peer holds the tag), and `kicker`
  (`attached` when a live auto-kicker is pumping the slot; `none`
  otherwise) plus `kicker_interval_ms`. A caller can now tell "armed
  and protected" from "armed and un-kicked" without a second call.
- **E-1c · foreign-owned + collision refusals on `arm`** — a bare
  `watchdog_manage(action="arm", id=N)` for an id another peer owns
  now returns `{ok: False, kind: "foreign_owned"}` (bypassable with
  `replace=True`), and re-arming an id the driver already has
  registered surfaces as `{ok: False, kind: "watchdog_collision"}`
  with an `auto_kick` nudge in the hint instead of the driver's raw
  `STATUS_OBJECT_NAME_COLLISION`. A successful `arm` claims the
  ownership tag so the next foreign arm hits the refusal, and every
  successful `arm` without a paired auto-kicker attaches a warning
  spelling out that the deadline WILL fire without something kicking.
- **E-1d · `disarm` releases the ownership tag** — a peer that
  disarms a watchdog id now drops its `watchdog:<view>` tag as well
  as cancelling any attached auto-kicker, so a follow-up `arm` (by
  any peer) is unblocked without needing `replace=True`.
- **E-2a · rotating JSONL audit writer** — new
  `orchestrator/src/suspex/audit.py` module ships an
  `AuditWriter(session_id, base=None)` sink and a `query(session_id,
  owner=?, method=?, since_iso=?, until_iso=?, limit=?, base=?)`
  reader. Files live under `~/.suspex0/audit/<session_id>/`, roll on
  size (`SUSPX_AUDIT_ROLL_BYTES`, default 16 MiB) and day (UTC
  midnight), and files older than `SUSPX_AUDIT_RETAIN_DAYS` (default
  14) are reaped on writer open. `SUSPX_AUDIT_DISABLE=1` shorts the
  whole pipeline for tests. Writer errors are counted (`writer.dropped`)
  but never raise — the tool call is authoritative.
  Also publishes a `DeadlineContext` dataclass + `build_deadline_context`
  stub — the shape F-3a will consume in v0.17.1 when
  `deadline_exceeded` classification grows queue/in-flight context.
- **E-2b · `Session.record_tool_call` mirrors to the audit sink** —
  `Session.__init__` now instantiates an `AuditWriter` scoped to a
  deterministic-per-boot `orch-<pid>-<epoch>` session id; every
  `record_tool_call` appends `{ts, tool, action, destructive, args,
  ok, error, owner}` to the JSONL ring. Ring capacity + wipe-on-restart
  are unchanged; the disk sink is additive. `SUSPX_AUDIT_BASE_DIR`
  overrides the base directory for tests.
- **E-2c · `target_manage(action="recent_ops", persistent=true)`** —
  routes the query to the on-disk JSONL audit sink instead of the
  in-memory per-client ring, so a caller can reconstruct tool
  history across orchestrator restarts. Filters: `op_method` (matches
  either `action` or `tool`), `op_owner` (client_id), `since_iso` /
  `until_iso` (ISO-8601 time bounds). `samples` caps the row count
  (default 500). Response carries `{persistent: true, session_id,
  count, ops}`.
- **E-3b · `target_manage(action="reconnect")`** — replaces a stale
  or wedged client for a view without going through the
  `disconnect` → `connect` dance (which would drop every co-owner's
  refcount). Endpoint + co-owner refs are preserved; the gRPC
  channel is torn down and a fresh `AgentClient` is built. Refuses
  on unknown view with `kind:"no_target"`. Emits a warning
  reminding the caller that anything in flight on the old channel
  was cancelled.
- **E-3c · degraded-view warn banner on `target_manage(status)`** —
  every connected view that has been silent longer than
  `SUSPX_DEGRADED_WARN_MS` (default 5000 ms) gets a warning row
  suggesting `target_manage(reconnect, name=<view>)`. A stale
  channel doesn't necessarily mean anything is broken, but during
  active tool use it's a strong hint the peer wedged.

## v0.16 (2026-09-15) — Operational polish: scan jobs, driver fixes, IDA ergonomics (full-stack rebuild)

Addresses three blockers and eight friction points from a live-session
operational review. Ships as one bundled release — proto (ABI v10),
driver, agent, orchestrator, and the vendored ida-pro-mcp plugin all
change together.

**Blockers fixed:**

- **Long-running pattern_scan job surface** — a 16 GB kernel scan used
  to blow the ~2 min MCP deadline with the results orphaned. New
  `mem_rw scan_start / scan_status / scan_result / scan_cancel /
  scan_list` actions: `scan_start` returns a `scan_id` immediately;
  status/progress polls the running task; `scan_cancel` sets a cancel
  Event the runner observes between chunks. Requires `address` + `size`
  (cancellable client-side chunked path); small whole-space calls stay
  on `pattern_scan`. Ownership tagged via v0.15 caller.py — foreign
  peers can `scan_status` / `scan_result` but not `scan_cancel`. Wire
  path: proto grows `Memory.ScanStream(PatternScanRequest) returns
  (stream PatternScanChunk)` alongside the legacy unary `Scan`, and
  `agent/src/grpc/services.cpp:Scan` gains `ctx->IsCancelled()` checks
  so client-side teardown actually stops the loop.
- **pool_scan fake matches** — driver-side `Pool.c:187-210` used to
  silently skip the content-filter branch when `pattern_len > 0` but
  `span == 0` and emit every considered entry with `MatchedOffset=0`.
  Orchestrator now refuses `pattern` without `size>0` with `bad_arg`;
  the driver returns `STATUS_INVALID_PARAMETER` for the same shape as a
  belt-and-braces. Response envelope grows `content_filter_active` so
  callers who did supply a filter can confirm it fired.
- **`mem_rw handles` NoneType crash** — `AgentClient._call` grows one
  defensive `if result is None` guard (with the method name in the
  raised RuntimeError) so downstream callers surface an actionable
  message instead of `AttributeError: 'NoneType' object has no
  attribute 'status'`. Covers every consumer of `_call`, not just
  `handle_list`.

**Friction cleared:**

- **IDA arg-name aliases** — `orchestrator/idalib_stdio_shim.py`
  `_call_passthrough` rewrites the alias arg names callers reach for
  (`search_structures.name→filter`, `disassemble_function.address→
  start_address`, `list_functions.limit→count`,
  `get_global_variable_value_by_name.name→variable_name`, plus a few
  more) to the canonical vanilla-plugin spelling. Alias tables live in
  the new `orchestrator/ida_shim_ergo.py` so pytest can exercise them
  without an IDA runtime.
- **decompile_function fallback** — when Hex-Rays fails (mid-function
  address, no licence, corrupted analysis), the shim auto-retries with
  `disassemble_function(start_address=address)` and returns a
  `status:'fallback_disasm'` envelope carrying both the original error
  and the disasm text.
- **`get_struct_member(struct_name, member_name)`** — new tool in
  `orchestrator/suspex_idalib_ext.py` that returns one field's
  `{offset, size, type, comment}` instead of the 28 KB / 232-member
  dump `analyze_struct_detailed` produced. Typed errors:
  `struct_not_found`, `member_not_found` (with a
  `known_fields_preview`), `not_a_udt`.
- **`get_xrefs_to_field` distinguishability** — the vendored ida-pro-mcp
  plugin at `.ida-mcp-venv/…/mcp-plugin.py:1043-1051` used to silently
  `return []` on unknown struct/field. Both silent returns are now
  `raise IDAError(...)`, so `[]` unambiguously means "no xrefs". The
  patch is recorded in `orchestrator/tests/README-vendored-patches.md`
  for reproduction after a `pip install --upgrade ida-pro-mcp`.
- **"None is not of type 'string'"** — schema-driven None→"" coercion
  in the shim rescues the mcp SDK output-validator refusal caused by
  the vanilla plugin's anonymous-type responses. Scoped by
  outputSchema so we don't hide legitimate None signals on non-string
  fields.
- **`file_manage grep_artifact` accepts bare sha256** — the same
  `_spill._resolve_by_sha` helper `read_artifact` already used. New
  `file_manage list_artifacts` sub-action enumerates the spill store
  (sha, kind, size, mtime, path — sorted newest-first) so callers
  never need a `bash` detour. `list_dir` docstring clarifies it
  targets the REMOTE target VM.
- **`INVALID_ADDRESS` classification** — `_error_enrich.py` reorders
  `HINT_RULES` so specific NTSTATUS rules
  (`STATUS_INVALID_ADDRESS|C0000141`, `STATUS_PARTIAL_COPY`,
  `ERROR_NO_SYSTEM_RESOURCES`) fire BEFORE the `driver: DeviceIoControl
  gle=` catch-all. Regression tests lock in both the new order and the
  existing pure-driver-absent path.
- **`driver_load` / `driver_unload` return full state** — after a
  successful RPC, orchestrator merges a `c.status()` probe
  (`driver_state`, `driver_present`, `driver_version`, `service_state`)
  into the response envelope. No more follow-up `status` call to
  confirm the SCM operation.

**Config additions:** none. All v0.15 knobs
(`clients.idle_reap_s`, `leases.{attach,driver}_timeout_s`,
`multi_agent.enabled`) still apply.

**Rebuild recipe (full-stack):**

- `.\scripts\gen_proto.ps1` — regenerate proto stubs for the new
  `ScanStream` RPC + `PatternScanChunk` message.
- `.\scripts\build.ps1` — build agent + driver.
- `.\scripts\sign_driver.ps1` — driver bump requires re-sign.
- `orchestrator\.venv\Scripts\python scripts\update_target.py --component all`
  — push agent + driver to the target VM.
- Existing agent/driver pairs continue to work for every action except
  `mem_rw scan_start` (which needs the new `ScanStream` RPC on the
  agent side).

## v0.15 (2026-09-15) — Multi-agent coordination layer (orchestrator only)

Multiple MCP clients (Claude Code, Kilo, Cursor, agent frameworks) can now
attach to one suspex0 orchestrator at the same time without silently
clobbering each other's state. Every tool dispatch is attributed to a
stable `client_id`, mutations of a peer's target-level state are gated
with a `foreign_owned` refusal + `force=true` override, and the two
genuinely single-owner resources on a target (per-pid DbgEng attach and
driver load/unload) are serialised with a `busy` envelope that names the
holder.

**No agent, driver, or proto changes** — coordination lives entirely in
the orchestrator. Existing agent + driver binaries keep working.

**New modules** in `orchestrator/src/suspex/`:
- `caller.py` — `CLIENT_ID` ContextVar populated from the streamable-HTTP
  `Mcp-Session-Id` header by a FastMCP `on_call_tool` middleware. STDIO
  and in-memory transports fall back to `anon-<host>-<hex>-<ns>`. Honours
  a pre-set ContextVar so tests / dashboard SDK calls can pin identity.
- `clients.py` — `ClientRegistry` with per-peer `held_attach_pids`,
  per-view refcounts, idle reap (default 300s, spawns from lifespan),
  and an SSE-style `subscribe()` bus that the lease manager publishes
  acquire/release events onto.
- `leases.py` — `LeaseManager` (async `Condition`-based) with
  `acquire(resource, owner, wait_s)` returning `LeaseHandle | BusyInfo`,
  `release_by_owner()` for peer reap, `snapshot()` for the dashboard,
  and `LeaseHandle` as an async context manager.
- `ownership.py` — `OwnershipRegistry` for non-leased primitives. Bulk
  `annotate(rows, id_field, current_owner)` stamps `owner` + `foreign`
  on list-shaped responses; `is_foreign_or_none()` returns the tri-state
  gate result for mutating actions.

**Tool-surface changes:**
- `target_manage`:
  - `connect(name, force=false)` — first connector owns the view;
    subsequent connects add co-owners (`shared=true`, `primary_owner`
    named in the response); refcount decrements on `disconnect`;
    `force=true` re-enables today's silent takeover for admin recovery.
  - `driver_load` / `driver_unload` acquire the `driver` lease with
    `leases.driver_timeout_s` wait; unload additionally refuses with
    `in_use_by=[peers]` when other owners still hold the kernel view.
  - New sub-actions: `whoami`, `list_peers`, `release_peer(peer_id,
    force=true)`, `subscribe_peers` (point-in-time snapshot; live SSE
    lives on the dashboard).
- `debug_manage`:
  - `launch` / `attach` acquire `debug:<view>:pid=<pid>` — a peer's
    attach on the same pid returns `busy` with `held_by` / `since_iso` /
    `waited_s`, or waits up to `leases.attach_timeout_s`.
  - `detach` releases every debug lease this owner holds on the view.
  - `continue` / `step_into` / `step_over` / `set_regs` / `write` / `cmd`
    gate through `_gate_mutation()` and refuse `foreign_owned` unless
    `force=true`. `regs` / `threads` / `stacktrace` / `read` / `regions`
    / `events` stay observational and unmediated.
- `bp_manage`:
  - `add` claims `bp:<view>` ownership on the returned `bp_id`.
  - `list` decorates each row with `owner` + `foreign=true|false|None`.
  - `remove` / `enable` / `disable` refuse foreign bps with
    `foreign_owned`; `force=true` overrides and (on remove) releases the
    tag.
- `exec_manage`:
  - `start_shell` / `run_detached` claim their returned id
    (`exec_shell:<view>` / `exec_detached:<view>`).
  - `write_console` / `read_console` / `stop_shell` /
    `detached_status` / `detached_tail` / `detached_kill` gate on the
    id's owner; `force=true` overrides.
- `ida_manage`:
  - `open` / `open_async` accept `share=true` and pass `owner` through
    to the bridge; a peer using the same friendly name for a different
    path gets a `<name>#<hex>` public name instead of a hard error.
    Same-name-same-path with `share=true` co-opens the existing worker.
  - `close` accepts `force=true`; a co-owner just detaches, the last
    owner triggers a real `idb_close`, and a primary handing off to a
    remaining co-owner promotes one.
  - `list` calls `bridge.sessions_snapshot(current_owner)` and returns
    per-session `owner` / `co_owners` / `foreign` / `shared` decorations.

**Internal wiring:**
- `Session.connect(owner=..., force=...)` returns `shared` /
  `primary_owner` / `forced_takeover`; `disconnect(owner=...)`
  refcount-decrements and only closes on last owner. `release_by_owner()`
  drops every ref held by a client id (called from the lease reap path).
- `Context` grows `clients`, `leases`, `ownership` (all keyword-only for
  backwards compat), `_attach_leases: dict[(view,pid), LeaseHandle]`,
  and per-caller `current_session_id: dict[client_id, str]` with
  `get_/set_current_session_id()` helpers.
- `AgentClient._call` and `log_follow_iter` stamp `client_id` on every
  `_recent_ops` ring entry so `target_manage recent_ops` attributes each
  gRPC call to its caller.
- `IdaBridge._sessions` internally namespaced by `(client_id, name)`
  with a `_co_owners: dict[name, set[client_id]]` map and public-name
  synthesis on collision.

**Config additions** (all optional, existing YAML keeps working):
- `clients.idle_reap_s` (default 300.0)
- `leases.attach_timeout_s` (default 5.0) — wait on attaching a peer's pid
- `leases.driver_timeout_s` (default 10.0) — wait on driver_load/unload
- `multi_agent.enabled` (default true) — master feature flag

**Rebuild recipe:**
- Orchestrator only: reinstall the wheel or `uv sync` inside
  `orchestrator/`. Restart the MCP server. Existing MCP clients keep
  working; the response envelope on `target_manage connect` grows
  `shared` / `primary_owner`, and list-shaped bp/exec/IDA responses
  grow `owner` / `foreign` fields.
- No proto bump, no ABI change. Agent + driver stay as-is.

## v0.14 (2026-09-15) — Unified MCP envelope + auto-spill + wire limits (full-stack rebuild)

Every `@mcp.tool` action now returns the same envelope shape, oversize
payloads auto-spill to on-disk artifacts, every list-returning action
speaks one paging contract, and the wire-level list RPCs carry
`limit`/`offset` fields (with `max_bytes` on `MemoryReadRequest`). **This
is a shape-breaking change and an ABI bump** — every consumer that
speaks MCP must adapt to the new response layout, and agent + driver
must be rebuilt for the ABI v8 → v9 bump.

**New envelope shape:**
```
{
  "ok": bool,
  "kind": str,                 # shape discriminator ("read"|"modules"|"handles"|...)
  "tool": str, "action": str,
  "data": <shape-specific>,    # lists live at data.items uniformly
  "summary": {"elapsed_ms", "size_bytes", "item_count"?,
              "item_total"?, "truncated"?, "next_cursor"?},
  "artifact"?: {"sha256", "size", "content_type",
                "preview", "replay_hint"},
  "warnings"?: [str],
  "error"?: {"error", "kind", "hint"?}   # only when ok=false
}
```

**Highlights:**
- Failure envelopes carry `{error: {error, kind, hint}}` nested, not flat
  at the top level. Every `_j({"ok": False, ...})` site still works — the
  `_guard` install site parses legacy strings and re-shapes them.
- `SUSPX_MCP_MAX_BYTES` (default 32 KiB) triggers auto-spill: the biggest
  field in `data` is written to `artifacts/spill/<sha256>.<ext>`, replaced
  by a compact preview + `env.artifact` slot. Fetch back via
  `file_manage(action="read_artifact", sha256=..., offset=... | page=...)`.
  Hex-string fields spill as raw bytes (halves storage); lists of dicts
  spill as `.jsonl` with an `.idx` sidecar for O(1) page seek. Content is
  sha256-addressed so identical payloads dedupe naturally.
- Compact by default: `_int` mirrors dropped unless `verbosity="full"` or
  `include_int=True`; `_flag` wrappers (`{value, source}` around booleans)
  collapse to the bare value unless `verbosity="full"`; `_decoded` enum
  siblings stay at `verbosity>="normal"` for the small allowlist that
  needs them.
- Unified paging on `mem_rw modules` / `handles` / `process_list`:
  `limit`/`offset`/`cursor`/`fields`/`filter`/`summary`/`verbosity` kwargs.
  Old cap names (`max_results`, `max_frames`, `max_matches`, `count`,
  `samples`, `tail_bytes`, ...) still accepted as aliases for `limit`.
  Uniform `data.items` shape replaces the old `{modules: [...]}` /
  `{handles: [...]}` / `{processes: [...]}` drift; `kind` names the shape.
- Env knobs: `SUSPX_MCP_MAX_BYTES` (spill budget, 32768), `SUSPX_MCP_MAX_ITEMS`
  (global list cap, 256), `SUSPX_MCP_PREVIEW_BYTES` (inline preview budget,
  512). Sandboxed under `artifacts/spill/`.

**Unified paging on every list-returning action:**
`mem_rw` (modules / handles / vad / process_list / pool_scan /
pattern_scan / disasm), `debug_manage` (threads / stacktrace / regions /
events / regs), `file_manage grep_artifact`, `findings_manage list`,
`script_manage history`, `reg_manage enum` — all take shared
`limit` / `offset` / `cursor` / `fields` / `filter` / `summary` /
`verbosity` kwargs. Old cap names (`max_results`, `max_frames`,
`max_matches`, `count`, `samples`, `tail_bytes`) still accepted as
aliases for `limit`. Uniform `data.items` shape everywhere; `kind`
names the shape.

**Wire-level `limit`/`offset` on the proto (ABI v8 → v9):**
`ModulesRequest`, `VadRequest`, `HandleListRequest`,
`ListProcessesRequest`, `ModuleImportsRequest`, `ModuleExportsRequest`,
`PhysRangesRequest`, `MemoryRegionsRequest` grew
`{int32 limit, int32 offset}` (0 = uncapped). `MemoryReadRequest` grew
`uint64 max_bytes` — driver-side hard byte cap independent of `size`,
clipping to `min(size, max_bytes)` before the maxMemReadBytes ceiling.
The C++ agent handlers apply these as post-fill slices (the underlying
driver APIs are buffer-fill-only), so gRPC serialization + wire bytes
shrink even without a native-driver bound. `SUSPEX_ABI_VERSION` bumped
from 8 to 9; existing `RunDriverGate` rejects mismatched pairs.

**IDA overflow folded into the shared artifact slot:**
Legacy `__suspex_pending` / `__suspex_chunked` magic-key envelopes are
gone. `ida_manage` passthroughs that exceed
`SUSPX_IDA_JOB_SOFT_DEADLINE_S` (25 s) or `SUSPX_IDA_JOB_CHUNK_BYTES`
(24 KiB) now emit
`{ok:true, kind:"artifact", tool:"ida_manage", action, data:{job_id,
preview}, summary:{item_total, size_bytes, truncated, next_page},
artifact:{sha256, size, content_type:"listing", preview, replay_hint}}`.
The full listing bytes land at `<spill_dir>/<sha256>.listing`, and
`file_manage(action="read_artifact", sha256=..., page=..., page_size=...)`
serves them by content hash — the payload survives the JOBS retention
window because it's on disk, not just in memory. `_ida_result` still
accepts `job_id=` for callers that already have one from a `pending`
response, and gains `sha256=` for content-addressed fetches.

**Rebuild:** full stack.
- **Driver** — no code change, but the ABI-version guard needs the new
  header (`scripts/build.ps1 -Target driver`, `scripts/sign_driver.ps1`,
  `scripts/update_target.py --component driver`).
- **Agent** — `services.cpp` handlers were updated to honor
  `limit`/`offset`/`max_bytes`. Rebuild and redeploy via
  `scripts/update_target.py --component agent`.
- **Orchestrator** — pip reinstall or restart the running process;
  `scripts/gen_proto.ps1` was already run to regenerate the Python
  bindings.

**Verify:** `pytest orchestrator/tests -k "envelope or spill or paging or shim_jobs"`
(60+ tests); full suite passes 373.

**Env knobs (all `SUSPX_*`):**
- `SUSPX_MCP_MAX_BYTES` — response byte budget; over this the biggest
  field in `data` spills. Default 32768. -1 disables spill.
- `SUSPX_MCP_MAX_ITEMS` — global cap on list length across every
  list-returning action. Default 256.
- `SUSPX_MCP_PREVIEW_BYTES` — bytes/chars kept inline as `preview` when
  a payload spills. Default 512.
- `SUSPX_MCP_SPILL_DIR` — override for `<artifacts>/spill/`. Also read
  by the IDA shim so its `.listing` files land in the shared directory.
- Existing `SUSPX_IDA_JOB_*` env vars unchanged.

## v0.13.2 (2026-09-15) — VA_TRANSLATE fix (driver rebuild)

`drv_exerciser physwr-verify` failed `vatrans` with `0xC0000141`
(STATUS_INVALID_ADDRESS) on build 26200. Two stacked defects in
`SuspxTranslateVa` (driver/src/Physical.c):

1. **Page-table reads used the broken physical-read primitive.**
   `SuspxPhysRead64` mapped page-table pages with
   `MmMapIoSpace(MmNonCached)`, which returns NULL for normal RAM on
   modern builds (the exact v4 issue — gle=1450). Every walk failed at
   the PML4 read, user and kernel VAs alike. Fixed: `MmCopyMemory`
   (MM_COPY_MEMORY_PHYSICAL) primary, `MmMapIoSpaceEx(PAGE_READONLY)`
   fallback — same shape as the v4 data-read path.
2. **Kernel VAs were walked against the IOCTL caller's CR3.** With KVA
   shadow active the usermode CR3 has no kernel mappings, so even a
   working walk reports valid kernel VAs as unmapped. Kernel VAs
   (`>= 0xFFFF8000_00000000`) now resolve via
   `KeStackAttachProcess(PsInitialSystemProcess)` +
   `MmGetPhysicalAddress` — the documented API, correct under any
   paging-mitigation layout. User VAs keep the manual 4-level walk in
   the caller's context.

Rebuild: driver only (`scripts/build.ps1 -Target driver`), re-sign
(`scripts/sign_driver.ps1`), redeploy
(`scripts/update_target.py --component driver`). Verified on 192.168.56.10:
`physwr-verify` PASS (kva→pa + phys read-back + map-write semantics),
`vatrans` on ntoskrnl base and on a user image base both PASS, full
driver gate green.

Build-host note: if the WDK `km`/`wdf` headers vanish after a Windows
SDK update, recover without admin via the WDK NuGet package
(`Microsoft.Windows.WDK.x64` on nuget.org — extract `c/` as the
`SUSPEX_WDK_ROOT`).

## v0.13.1 (2026-09-14) — Phase 3 withdrawn; ABI back to v8

The Phase 3 Windows Sandbox surface (`exec_manage run_sandbox` /
`sandbox_status` / `kill` / `list`, the `host_info` sandbox_capability
probe, the agent-side `SandboxRegistry`, and the ABI v9 proto messages)
was withdrawn: live testing on the nested-VM lab target hit fast-fails
(`0xC0000142`), multi-minute boots, and a hard guest crash — Windows
Sandbox inside a VM without reliable nested virtualization + GPU is not
viable. `emulate_manage` covers the use case (obfuscation / shellcode
verification) without a VM. For real execution, use a disposable VM
with snapshot rollback. ABI returns to v8; the brief v9 added nothing
else.

## v0.13 (2026-09-11) — codegen + emulate

Three phases; see [docs/CODEGEN.md](docs/CODEGEN.md) for the analyst
walkthrough and [.kilo/plans/2026-09-11-codegen-craft-emulate.md](.kilo/plans/2026-09-11-codegen-craft-emulate.md)
for the pre-implementation plan.

- **Phase 1 — `mem_rw disasm` / `mem_rw assemble` (orchestrator-only).**
  Capstone-backed decode and Keystone-backed encode; pure-compute when
  the caller supplies `bytes_hex` / `code`, target-touching when they
  supply `address` (read then decode) or `write_to` (assemble then
  write). Write path stays gated on `dry_run=false` with a named
  `unsafe_default` refusal — silent target writes are structurally
  impossible.
- **Phase 2 — `emulate_manage` (orchestrator-only).** Session-ful CPU
  emulation with Speakeasy (default, Windows veneer + hooked APIs) or
  Unicorn (escape hatch, snapshots supported). Every session mirrors
  the `ida_manage` shape — `create` → many step / regs / hook calls →
  `close`. **`seed_from_target`** pulls live regs + memory blobs off
  the target and hydrates the emulator so the LLM can step from the
  exact CPU state the real thread sees.
- **Phase 4 — `craft_test` reference plugin**
  ([plugins/craft_test/](plugins/craft_test/)). Demonstrates
  the full `assemble → disasm-verify → emulate` loop. `sdk.codegen` /
  `sdk.emu` facades expose the same machinery to every plugin.

**Install**: `pip install 'suspex0[codegen]'` (adds capstone /
keystone-engine / unicorn / speakeasy-emulator).

**Rebuild recipe:** codegen/emulate are orchestrator-only. No agent or
driver rebuild for Phase 1/2/4 — they live in the orchestrator. After
`git pull`, restart the orchestrator process. The withdrawn Phase 3
needed an agent rebuild; current agent builds carry ABI v8 again.

## v8.1 driver-only refresh (2026-09-10)

Follow-up per [.kilo/plans/2026-09-10-dpc-watchdog.md](.kilo/plans/2026-09-10-dpc-watchdog.md).
Rewrites `driver/src/Watchdog.c` from a HIGH_PRIORITY system thread
runner to a periodic KTIMER + KDPC ticking at 100 ms. Wire ABI stays
at v8; `SUSPEX_DRV_VERSION_MINOR` bumps 0 → 1 so `drv_exerciser ping`
shows the runner mechanism. The DPC runner catches wedges that starve
threads (dispatcher-lock spins, DPC storms pinning every CPU at
DISPATCH+, scheduler bugs) that the v8 thread runner cannot — timer
DPCs fire off the per-CPU clock interrupt above the thread scheduler.

Tradeoff: `ZwWriteFile` is illegal at DISPATCH_LEVEL so the on-disk
`WDG FIRE` line is gone; the DPC uses `DbgPrintEx` instead (captured
in `KdPrintCircularBuffer`, readable via `!dbgprint` in windbg on the
dump). The four bug-check args stay the primary provenance path.

**Driver-only redeploy:**

```powershell
# on the build host
.\scripts\build.ps1                  # rebuilds driver (user-mode unchanged, links no-op)
.\scripts\sign_driver.ps1            # driver bump — re-sign required
# on the target VM
sc \\<ip> stop SuspexAgent           # stops agent → driver_unload
# copy fresh suspex_driver.sys, then:
sc \\<ip> start SuspexAgent          # restarts agent → driver_load (v8.1 runner)
.\scripts\verify_roundtrip.ps1 -Computer <ip>       # wdg-smoke still passes
```

No orchestrator restart needed — the wire surface didn't change.
Verify by inspecting the ping output: `drv_exerciser ping` reports
`v<major>.<minor>`; `<minor>` = 1 identifies the DPC runner.

## v0.11 / ABI v8 (2026-09-10) — watchdog + live log follow

Two capabilities addressing the silent-wedge / lost-verdict failure
mode:

- **`Watchdog` service (`watchdog_manage` MCP tool).** Driver-side
  8-slot table; arming a slot registers an absolute deadline, the
  driver `KeBugCheckEx(0xE2, Id, DeadlineUs, LastKickUs, Cookie)`s
  the target when the deadline passes without a kick.
  `watchdog_manage(action="auto_kick", ...)` arms and spins an
  orchestrator-side kicker on cadence — any wedge in the LLM loop
  that outlasts the deadline turns into an analyzable dump instead
  of a manual power cycle. The four bug-check arguments make the
  dump self-identify under `!analyze -v`.
- **`Files.LogFollow` server-streaming RPC (`file_manage
  follow_start/follow_poll/follow_stop/follow_list`).** `tail -f`
  from the target agent to the orchestrator, ring-buffered per
  follow_id so the LLM polls. Reads verdicts out of a LIVE wedge —
  `exec_trace.log` / `layer2check.log` writes flush-per-line to
  disk on purpose; the follower reads them without a reboot pull.

**ABI v8 rebuild recipe:** full-stack rebuild + driver re-sign
(proto + comm + driver + agent all carry the v8 surface):

```powershell
# on the build host
.\scripts\build.ps1                  # rebuilds driver + agent + proto stubs
.\scripts\gen_proto.ps1              # already run by build.ps1; safe to repeat
.\scripts\sign_driver.ps1            # driver bump — re-sign required
.\scripts\deploy_to_vm.ps1 -Computer <ip>
# on the target VM (or use the deploy script's -InstallService)
sc \\<ip> stop SuspexAgent
sc \\<ip> delete SuspexAgent
# copy the new files over, then install fresh:
sc \\<ip> start SuspexAgent
.\scripts\verify_roundtrip.ps1 -Computer <ip>       # wdg-smoke gate included
```

Orchestrator (v0.11+) on a v7-agent target: `watchdog_manage` returns
a named `agent < v8` error; `file_manage follow_start` returns a
named `agent < v8` error and the caller falls back to polled
`file_manage tail`.

## v0.10 / ABI v7 (2026-09-09)

Three phases; source plan at
[.kilo/plans/2026-09-09-dev-feedback-improvements.md](.kilo/plans/2026-09-09-dev-feedback-improvements.md).

**Phase 0 — orchestrator quick wins (hot-reload, no rebuild):**

- `target_manage status` / `sysinfo` — driver-sourced fields
  (`testsigning`, `hvci`, `patchguard_expected`) are now wrapped in
  an envelope `{value, confidence: "driver-absent-default",
  note: ...}` whenever `driver_state != loaded`, with a top-level
  `driver_present: bool`. Pre-load recon no longer misleads.
- `target_manage host_info` (**v8**) — broad target fingerprint on
  top of what `sysinfo` reports: identity (computer / dns / domain,
  logged-on user, agent-run-as, is_elevated), full OS release
  (product name, edition, display version, release id, UBR-included
  build string like `26200.9186`, install date, boot time, timezone,
  arch), security posture with per-flag `{value, confidence,
  source}` — the driver-verified bits win when the driver is loaded,
  else `usermode-registry` or `usermode-api` — covering testsigning,
  HVCI, secure boot, kernel debugger, VBS, credential guard, driver
  blocklist, LSA-PPL, SMEP, SMAP, CET shadow stack; optional
  hardware (CPU brand / cores / mem, hypervisor vendor + `is_vm`);
  PC / agent-process / SCM service uptimes.
  `include_security_products=true` opts into a WSC scan (empty in
  v8, wired in the follow-up slice). Older agents get a clean
  `{ok:false, error:"agent < v8 ..."}` — no wedge.
- `target_manage targets` — returns `views: [{name, endpoint,
  configured_endpoint, state:
  connected|connected_stale|not_connected, last_seen_ts, last_op_ts,
  seconds_since_last_op, connected_ts, primary}, ...]` alongside
  the legacy `connected` list. Post-reboot reconnect is
  deterministic.
- `target_manage crash_state` — one call that stitches
  `recent_ops_agent` + kernel-log tail (default 32 KiB) + reboot
  detection (agent uptime vs last-seen delta) into a single JSON
  response.
- `file_manage tail` — server-side tail-N-bytes. Prefers
  `Files.LogTail` RPC (Phase 1), falls back to `Hash`-for-size +
  ranged `Download`. Kills the 234 MB kernel-log pull pattern.
- `exec_manage` docstring — hard DEADLINE_EXCEEDED cascade warning
  steering to `start_shell` / `read_console` or the new
  `run_detached`.
- `mem_rw` docstring nudge — one-line inventory saying every driver
  IOCTL is reachable here (`pool_scan`, `handles`, `imports` /
  `exports`, `heaps`, `vad`, `phys_ranges`, `va_translate`, `watch`,
  `probe_va`).

**Phase 1 — agent additions (agent rebuild, no driver, no ABI bump):**

- `Files.LogTail` RPC — agent reads the last N bytes of a file
  locally with `FILE_SHARE_READ|WRITE|DELETE`, seeks from end,
  `line_align=true` to skip the partial first line. Zero network
  cost.
- Kernel-log rotation on the agent — configurable
  `SUSPX_KERNEL_LOG_MAX_MB` (default 64 MB). When the on-disk file
  exceeds the cap, `<path>` is renamed to `<path>.old` (overwriting
  the prior `.old`) and the driver reopens fresh. `Files.LogTail(...,
  include_rotated=true)` stitches both files with a `--- rotated ---`
  marker.
- `RunExeResponse.killed` — populated when the agent had to kill the
  child on `timeout_ms`. The RPC returns cleanly with partial
  stdout; the channel stays alive.
- `Exec.RunDetached` family — `run_detached(cmdline, workdir, ...)`
  spawns with `CREATE_NEW_PROCESS_GROUP`, redirects stdout/stderr
  to per-handle log files under
  `%ProgramData%\suspex\detached\<handle>\`, returns `{handle_id,
  pid, stdout_path, stderr_path, started_ts}` immediately. Poll
  with `detached_status`, tail with `detached_tail`, clean up with
  `detached_kill`.
- `StatusResponse.agent_uptime_ms` — populated on every Status call
  so `crash_state` can detect a mid-session reboot without a second
  RPC.

**Phase 2 — full-stack ABI v7 (bumped `SUSPEX_ABI_VERSION` 6 → 7):**

- `mem_rw va_translate` — exposes the driver's CR3 page-table walk
  (`SUSPEX_IOCTL_VA_TRANSLATE`, shipped in ABI v5 without a wire
  surface). Returns `{pa, present, pa_hex, cr3, page_size_shift}`.
  KERNEL space only in v7; USER-space walks need
  `KeStackAttachProcess` handling on the driver — deferred.
- `mem_rw watch` — agent-side memory polling with a server-streaming
  gRPC RPC. One worker thread per active watch (bounded by
  `SUSPX_MAX_WATCHES`, default 8). Emits events on transition
  (`prev` / `now` bytes, `seq`, `ts_ms`); terminates on
  `duration_s`, `max_events`, client cancel, agent shutdown, or
  `SUSPX_WATCH_FAIL_LIMIT` consecutive read failures (default 5 —
  wedge detection; final event carries `read_failed=true`).
  Interval floor at `SUSPX_WATCH_MIN_MS` (default 10 ms). Companion
  actions `watch_list` and `watch_stop` operate on background-mode
  watches keyed by an orchestrator-issued `w<NNNN>` id. Short
  watches (duration ≤ 30 s, ≤ 32 events) run inline via
  `mem_watch_collect`.

**ABI v7 rebuild recipe:**

```powershell
# on the build host
.\scripts\build.ps1                  # rebuilds driver + agent + proto stubs
.\scripts\gen_proto.ps1              # already run by build.ps1; safe to repeat
.\scripts\sign_driver.ps1            # driver bump — re-sign required
.\scripts\deploy_to_vm.ps1 -Computer <ip>
# on the target VM (or use the deploy script's -InstallService)
sc \\<ip> stop SuspexAgent
sc \\<ip> delete SuspexAgent
# copy the new files over, then install fresh:
sc \\<ip> start SuspexAgent
.\scripts\verify_roundtrip.ps1 -Computer <ip>
```

Orchestrator (v0.10+) on a v6-agent target degrades cleanly: `mem_rw
va_translate` / `watch` / `run_detached` / `detached_*` /
`file_manage tail` (LogTail-native path) all return a named
`agent < v7` error and the caller can retry with the pre-v7
workflows. `file_manage tail` on a v6 agent silently falls back to
hash-for-size + ranged download so the "no 234 MB pull" property
holds even before the agent rebuild.

## v0.9 / ABI v6 (2026-09-06) — bp_manage + partial-read

Three fixes on `bp_manage` and pool sweeps:

**Orchestrator + agent (agent rebuild, no driver change):**

- **HW BPs always route through the driver.** `bp_manage(kind="hw")`
  no longer touches the DbgEng session at all — `kernel_target`
  becomes a display hint. Kills the "no active session" failure on
  user pids after idle (the dbgeng sub-session silently expires;
  the driver path doesn't have one).
- **SW BPs auto-attach + rebind.** `bp_manage(kind="sw")` runs
  `DbgSession::Attach(pid)` on demand if no session is live, and
  retries once transparently on stale-session errors
  (`no active session` / `E_UNEXPECTED` / `RPC_S_SERVER`). Look for
  `[dbg] auto-attached pid=X` / `[dbg] rebind pid=X` in the agent
  log.
- Docstring on `bp_manage` now documents per-thread / per-PID
  semantics explicitly — the `KUSER_SHARED_DATA` tick-BP "miss" is
  correct per-thread behaviour, not a bug.

**ABI v6 rebuild (driver + agent + re-sign):**

- **`SUSPEX_MEM_FLAG_PARTIAL 0x2` on kernel reads.** Per-4KB
  `MmCopyMemory` walk, stops at the first unmapped page, returns
  the valid prefix as `STATUS_PARTIAL_COPY`. `mem_rw read
  partial=true` surfaces `read_bytes` + `first_bad_offset`. Fixes
  the "1 MiB pool scan fails atomically on one bad page" workflow
  — seconds/GiB instead of minutes.
- **`SUSPEX_BP_HW_FLAG_GLOBAL 0x1` on HW BP set.** `bp_manage
  action=add kind=hw global=true` arms every existing thread of
  every process AND the `PsSetCreateThreadNotifyRoutine` hook
  catches newborns regardless of parent pid. Driver-side cap at 2
  concurrent global BPs so a runaway can't consume every DR slot
  on every thread. Pair with `dangerous_ok=true` for PG-defanged
  VMs (marker wiring is a follow-up).

**Orchestrator-only (no rebuild):**

- **`sdk._scan_range_impl` page-by-page salvage.** When a chunk
  read fails, retry a page at a time and consume the valid prefix
  instead of dropping the whole 1 MiB into `chunks_skipped`. New
  telemetry: `partial_chunks`, `partial_bytes` in `mem_rw
  pattern_scan` output. Works even against a v5 agent (no ABI
  dependency — pure client-side logic on top of the existing
  per-page failure signal).

**Rebuild recipe:** same as the v0.8 / ABI v5 recipe below
(`.\scripts\build.ps1` full rebuild including driver +
`sign_driver.ps1`). Orchestrator (v0.9+) on a v5 target: HW BPs
still work (driver-side change is agent-invariant); `partial=true`
on `mem_rw read` becomes an ignored proto field on the older
agent, and the driver falls back to legacy semantics.

## v0.8 / ABI v5 (2026-09-06) — physical write opt-in

`SUSPEX_ABI_VERSION` is now 5: the physical write path became
opt-in and fault-tolerant.

- **`SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE` (bit 2)** gates
  `PHYS_MEM_WRITE`. Without the flag the driver refuses cleanly
  (`STATUS_ACCESS_DENIED`); with it, the per-4KB `MmMapIoSpaceEx`
  loop skips pages it cannot map (first skipped offset is
  op-logged) and returns `STATUS_PARTIAL_COPY` with Done < Size
  instead of aborting.
- **`VA_TRANSLATE` IOCTL (`0x857`)** exposes the driver's CR3
  page-table walk (`SuspxTranslateVa`) so gates/tests can locate
  the physical backing of a known-good VA.
- `mem_rw write space=physical` requires `allow_map_write=true` on
  the orchestrator side (named client-side error otherwise).
- Exerciser gate: `drv_exerciser physwr-verify` (opt-in refusal →
  map write on its own pool → physical + kernel-VA read-back) and
  `drv_exerciser vatrans --addr 0xX`; `physwr-verify` is in the
  default `_local_kernel_test.ps1` matrix.

Driver, agent, and orchestrator must ship together again (full
rebuild + re-sign, recipe below). Orchestrator (v0.8+) on an older
target: physical writes without the flag fail with the client-side
named error; with the flag against a v4 agent the field is ignored
by the old agent — check `X-Suspex-Server-Version` / agent ABI
before relying on the new semantics.

### v0.8 orchestrator-only refresh (Phase C.T) — IDA transport hardening

Same server bump (0.8.0-2026-09-06); no agent or driver change.
Orchestrator hot-reloads. Fixes three failure modes hit on huge IDA
outputs:

- **Bridge `readline()` no longer crashes on 100 KB responses.**
  The `asyncio.create_subprocess_exec` limit for the shim's stdout
  is raised from the 64 KiB default to 32 MiB. Root cause was
  `ValueError: Separator is found, but chunk is longer than limit`
  on a single decompile_function line exceeding the reader cap.
- **Auto-promoted background jobs for any slow passthrough.** Any
  `ida_manage` call whose backend response takes longer than
  `SUSPX_IDA_JOB_SOFT_DEADLINE_S` (default 25 s) returns
  `{__suspex_pending: true, job_id, hint}` and keeps running under
  `asyncio.shield`. Kills the MCP -32001 timeout on
  `disassemble_function` and long `exec_idapython` jobs.
- **Auto-chunked large results.** If a passthrough response
  exceeds `SUSPX_IDA_JOB_CHUNK_BYTES` (default 24 KiB) the shim
  stashes it in a JOBS cache and returns `{__suspex_chunked: true,
  job_id, total_chunks, preview, hint}`. Caller pages via
  `ida_manage(action="result", args_json='{"job_id":"...",
  "page":0}')` and concatenates `data` across pages 0..N-1.
- **New `ida_manage` actions:** `job_start`, `job_status`,
  `result`, `job_cancel`, `job_list` (short verbs; the shim tools
  are `ida_job_start` / `ida_job_status` / `ida_result` /
  `ida_job_cancel` / `ida_job_list`). Job entries retain for
  `SUSPX_IDA_JOB_RETENTION_S` seconds after completion (default
  30 minutes).

## v0.7 (2026-09-06, Phase B) — agent-only

v0.7 orchestrator adds four capabilities on top of v0.6 / ABI v4.
They need an agent rebuild + redeploy (the driver is untouched — no
kernel signing dance):

- **Registry impersonation** — new `impersonate` field on every
  `reg_manage` action: `user_by_pid:<pid>` or
  `user_by_sid:<sid>`. Reaches HKCU of any user whose process the
  agent can open (SYSTEM can open all of them). RAII-scoped in
  `services_registry.cpp` so a failed handler never leaks the
  impersonation.
- **`Memory.ReadStream` server-streaming RPC** — for `size > 4
  MiB`, `mem_rw read` auto-uses `mem_read_all()` which iterates
  the stream and reassembles. Removes the manual-chunk dance for
  image dumps.
- **Persistent agent-side crash breadcrumb** — new
  `agent/src/breadcrumb.{hpp,cpp}` hooks `Driver::SetTraceHooks()`
  (from `comm/`) so every IOCTL logs a pre/post entry in a 64-slot
  ring persisted to `%ProgramData%\suspex\breadcrumb.bin`. Read
  via `target_manage(action="recent_ops_agent")` —
  `prior.status_kind == "wedged"` marks calls in flight when the
  previous lifetime died.
- **IDA `idb_save` / `ida_status` / `ida_log` + periodic saves** —
  extension entry registers three new tools and a background saver
  (`SUSPX_IDA_SAVE_EVERY_S`, default 120 s). Save target is
  guarded: refuses to overwrite the input .sys, always writes to
  `<input>.i64`. Shim gains `ida_log` returning the backend log
  tail — visible even after the backend just died — and
  `idb_list` now marks `backend_alive` + reaps dead sessions. The
  `idapro.save_database` guard is process-wide: ANY call site
  (hook script, `exec_idapython`, vanilla-server internals) that
  targets the input path, a non-database extension, or no path is
  redirected to `<input>.i64` with a `[suspx-guard]` log line.

**Rebuild recipe:** same as v0.6 / ABI v4 below (rebuild + sign is a
no-op for the driver since only the agent changed; you can just
`.\scripts\build.ps1 -SkipDriver` on the build host).

Orchestrator (v0.7+) survives a v0.6 / v4-agent target —
`mem_read_stream` / `recent_ops_agent` / `reg_manage
impersonate=...` degrade with a clean "agent < v5" error until the
target catches up.

## v0.6 / ABI v4 (2026-09-06) — physical memory rework

The v4 driver + agent adds the reworked physical-memory path
(MmCopyMemory first, per-call MmGetPhysicalMemoryRanges re-query),
the `phys_ranges` and `pool_scan` IOCTLs, and the `Registry` gRPC
service. Because the kernel ABI header (`comm/suspex_abi.h`
`SUSPEX_ABI_VERSION`) is versioned and ping-gated, the driver,
agent, and orchestrator must ship together.

**Rebuild recipe:**

```powershell
# build host
.\scripts\build.ps1                  # rebuilds driver + agent + stubs
.\scripts\sign_driver.ps1            # re-sign the driver
.\scripts\gen_proto.ps1              # (build.ps1 already does this)
.\scripts\deploy_to_vm.ps1 -Computer <ip>
# target VM (or use the deploy script's -InstallService)
sc \\<ip> stop SuspexAgent
sc \\<ip> delete SuspexAgent
# copy files over, then install fresh:
sc \\<ip> start SuspexAgent
.\scripts\verify_roundtrip.ps1 -Computer <ip>
```

Orchestrator (v0.5+) survives a v3-agent target — `pool_scan` /
`phys_ranges` / `reg_manage` calls just report `driver: LastError`
or `registry service unavailable` until the target catches up.
