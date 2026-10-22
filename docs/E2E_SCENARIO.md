# Suspex0 end-to-end scenario

LLM-free scripted path through the full toolchain: upload → run → debug → bp
hit → dump → IDA decompile → report. Run against a snapshot-reset lab VM with
TESTSIGNING ON and the agent service installed (`scripts/deploy_to_vm.ps1`).

## 0. Preconditions

```powershell
# build host
.\scripts\build.ps1
.\scripts\sign_driver.ps1            # test-sign suspex_driver.sys
.\scripts\deploy_to_vm.ps1 -Computer 192.168.56.10
# target VM
sc \\192.168.56.10 start SuspexAgent
.\scripts\verify_roundtrip.ps1 -Computer 192.168.56.10   # driver gate: MUST pass first
```

Orchestrator: `uv sync`, then `uv run suspex-server --config configs\example.yaml`
with the target host/token filled in. MCP endpoint: http://127.0.0.1:8765/mcp.

## 1. Scripted sequence (no LLM)

```python
# run with: uv run python docs/e2e_scenario.py   (see smoke_mcp.py for client boilerplate)
target_manage(action="connect")                                  # status shows driver+testsigning
target_manage(action="driver_load", method="service")            # service path (HVCI off for map path)
mem_rw(action="process_list")                                    # kernel-side process iteration
mem_rw(action="modules", pid=0, kernel=True)                     # kernel driver iteration
file_manage(action="upload", local_path="testdata\\victim.exe", remote_path="C:\\suspex\\victim.exe")
debug_manage(action="launch", cmdline="C:\\suspex\\victim.exe", break_on_entry=True)
bp_manage(action="add", kind="sw", address="0x140018078")        # hex strings work; ints too
mem_rw(action="pattern_scan", pid=<pid>, pattern="4D 5A ?? 90",  # IDA-style pattern + wildcards
       address="0x7ff600000000", size=0x100000)                  # range scan reports telemetry
debug_manage(action="continue")                                  # wait for bp hit event
debug_manage(action="events")                                    # BREAKPOINT_SW event surfaces
debug_manage(action="regs"); debug_manage(action="stacktrace")
file_manage(action="dump_module", pid=<pid>, module="victim.exe")
# ida_manage: `open` blocks up to the request deadline; use `open_async` for
# large drivers (returns pending in ~5s, poll open_status until ready).
ida_manage(action="open_async", path="artifacts\\dumps\\victim.exe", name="victim")
# ...poll: ida_manage(action="open_status", name="victim")  # -> ready
ida_manage(action="decompile", name="victim", args_json='{"address": "0x140018078"}')
findings_manage(action="record", severity="high", title="...", description="...",
                refs="bp transcript + decompile")
findings_manage(action="generate_report")                        # reports/report.md + .html
exec_manage(action="kill_process", pid=<pid>)
target_manage(action="driver_unload")                            # or reboot the VM
```

## 2. Pass criteria

- verify_roundtrip exit 0 (full IOCTL matrix incl. procs, mods, kalloc)
- mem write → read-back roundtrip identical (exerciser selftest)
- sw + hw bp hits surface as `BREAKPOINT_SW`/`BREAKPOINT_HW` events on the bus/WS feed
- upload → exec → download hash matches (`file_manage hash`)
- dump_module produces a file whose `idb_open` succeeds and `decompile` returns output
- findings ledger holds the recorded finding with evidence; report renders both formats
- `npx @modelcontextprotocol/inspector` lists the 10 suspex0 tools (`target_manage`, `mem_rw`, `debug_manage`, `bp_manage`, `exec_manage`, `file_manage`, `ida_manage`, `script_manage`, `findings_manage`, `reg_manage`)
- driver op log at `C:\Users\Public\Desktop\suspex_kernel.log` shows each IOCTL

## 3. Failure triage

| Symptom | Likely cause |
|---|---|
| driver gate ping fails | driver not loaded / not admin / TESTSIGNING off / cert not in target Root store |
| manual map refused | HVCI on (check `target_manage sysinfo`), disable VBS on the VM |
| APC remote call not queued | thread not alertable — use a fresh parked thread (mapper does) or kernel-mode flag |
| dump fails IDA load | module dump taken mid-write; re-dump at a bp where the image is quiescent |
| dbgeng symbols missing | set `_NT_SYMBOL_PATH` (config: `artifacts.pdb_cache`) |
| `ida_manage open` times out on a 100 MB+ binary | use `open_async` + `open_status` — first idalib analysis can outrun the MCP request deadline; the shim keeps working after the client gives up. For hand-driven analysis pass `run_auto_analysis=false` in `args_json` and use `create_function(address)` + `exec_idapython` on the interesting eas, then run `auto_wait`. |
| `ida_manage open` fails with "PE has duplicate section names" | The idalib PE loader crashes on this (nvlddmkm.sys is the reference case). Patch a copy of the PE to rename the duplicates (e.g. `.text` → `.text2`) and reopen from the patched path — the shim pre-validates the PE now and refuses this rather than reporting a mysterious rc=1. |
| decompiler blind on vtable-dispatched code | auto-analysis only carves functions where a direct call reaches them; vtable / computed-call targets never become functions. Get the ea from strings / xrefs, then `ida_manage(action="create_function", args_json='{"address":"0x…"}')`, then `decompile_function`. |
| need to find a buffer by pool tag | `mem_rw(action="pool_scan", module="EDID")` (module doubles as the 4-char tag). Add `pattern` + `size` (content_span) for content filtering; result carries `va`, `size`, `tag_ascii`, and `matched_offset`. |
| need real RAM ranges | `mem_rw(action="phys_ranges")` returns MmGetPhysicalMemoryRanges (re-queried per call). Sum of `size` = total system RAM; base+size boundaries are the addresses the physical read path will accept without needing MMIO fallback. |
| need to read a registry key | `reg_manage(action="get", hive="HKLM", subkey="...", value="...")` — decoded `str`/`qword`/`multi_sz` for common types, `hex` always populated. `enum` walks a subkey. |
| `pattern_scan` returns `[]` on a range | check the response `bytes_scanned`/`chunks_skipped` — zero scanned + N skipped means holes/PTE gaps, not "no hits" |
| gRPC read wedges the 10 s default | raise `mem_rw`'s `timeout_s` for slow kernel/physical reads |
| agent process died mid-run | `target_manage(action="recent_ops")` prints the last ~32 gRPC attempts with latency/status — shows what was in flight |
| tool returns `unknown action X` | the error lists every valid action for that tool; also `ida_manage(action="schemas")` for the full idalib-mcp tool inventory with input schemas |

## 4. v0.19 analysis-layer scenarios (manual)

These extend the base scenario — they need no new target-side setup.

### Static triage without IDA

1. `file_manage(action='dump_module', module='suspex.sys', kernel=true)` → note the artifact path.
2. `bin_manage(action='info'|'imports'|'imphash'|'sec', path='<dump>')` —
   identity, import surface, imphash, mitigation audit.
3. `bin_manage(action='irp_surface'|'ioctl_surface', path='<dump>')` —
   MajorFunction table, device names, CTL_CODEs decoded.

### irp_hook_check (live dispatch-table integrity)

1. Baseline: `script_manage(action='run', name='irp_hook_check',
   params_json='{"driver_object":"0x<drvobj_va>",
   "module_path":"<dumped suspex.sys>"}')` — expect `matched` on every
   slot. (`driver_object` is the `_DRIVER_OBJECT` VA — obtain via
   `!drvobj`, IDA `dt`, or an object-directory walk.)
2. Patch one live `MajorFunction[]` entry in the lab driver's
   `_DRIVER_OBJECT` (e.g. via `mem_rw write` on `driver_obj+0x70+8*0x0E`).
3. Re-run — expect `redirected_out` / `patched_inside` on that slot with
   the live vs expected VA pair in the finding evidence.

### code_integrity (inline-patch detection)

1. `script_manage(action='run', name='code_integrity',
   params_json='{"module":"suspex.sys",
   "disk_path":"<on-disk suspex.sys>"}')` — expect all `matched`.
2. `mem_rw write` a few bytes into the driver's `.text`.
3. Re-run — expect a `body_mismatch` finding naming the function whose
   normalized body-hash changed.
