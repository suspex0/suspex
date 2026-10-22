# Suspex0 SDK & Plugins

Phase-2 deliverable: a low-level Python SDK plus a plugin contract so any
agent (or human) can script low-level access — driver-backed kernel reads,
usermode cross-checks, module/process recon, debugging, findings — without
touching gRPC plumbing.

Authorized lab use only. No stealth/evasion features, ever.

---

## 1. The SDK (`suspex.sdk`)

`SuspexSDK` wraps the connected session clients plus the findings ledger:

```python
from suspex.sdk import SuspexSDK

sdk = SuspexSDK(clients={"kernel": kernel_client, "user": user_client},
                ledger=ledger, session_id=sid, nt_build=26200)
```

| API | Primitives |
|---|---|
| `sdk.mem` | `read/write/alloc/free/protect/regions` + `scan_range` (local chunked scan, works for kernel ranges too; skips holes), `snapshot(pid, ranges)` / `diff(snapshot, pid)` and `view(name)`. Use the module-level `scan_range_with_stats(client, pid, address, size, pattern, mask, space, chunk=…, max_results=…)` when you also want `{bytes_scanned, bytes_skipped, chunks_read, chunks_skipped, truncated}` telemetry — the MCP `pattern_scan` action calls this. |
| `sdk.mods` | `list(pid, kernel, view)`, `find(name, ...)` — returned dicts have int base/size (proto3-JSON strings normalized) |
| `sdk.procs` | `list(view)`, `find(image_substr)` |
| `sdk.dbg` | `launch/attach/detach/cont/step/regs/set_regs/threads/stack/read/write` (primary view) |
| `sdk.yara` | `scan_bytes(data, rule)`, `scan_module(pid, module, rule)` — requires the `yara` extra (`pip install suspex0[yara]`) |
| `sdk.codegen` | v0.13: `disasm(data, arch, syntax, address, count, detail)` (capstone), `assemble(code, arch, address) → (bytes, count, labels)` (keystone). Pure-compute — no target contact. Requires the `codegen` extra (`pip install 'suspex0[codegen]'`); a missing extra raises `codegen.CodegenUnavailable`. |
| `sdk.emu` | v0.13: `create(arch, mode, engine, flavor) → EmuSession`, `get(session_id)`, `close(session_id)`, `list()`. Session objects expose `engine.load_shellcode/run/step/regs/set_regs/mem_read/mem_write/map/unmap/add_hook/snapshot/restore`. Two engines: `speakeasy` (default, Windows veneer + hooked APIs) and `unicorn` (bare CPU, snapshots supported — use when the speakeasy install chain misbehaves). |
| `sdk.findings` | `record(severity, title, desc, refs)`, `evidence(finding_id, kind, content)` |
| `sdk.parity` | `parity(pid, samples, read_bytes, seed)` — kernel-vs-usermode harness (needs both views; transient mismatches on live memory are re-checked before reporting) |
| `sdk.clients` | raw `AgentClient` per view (`"kernel"`, `"user"`) — `client.recent_ops(limit=32)` returns the last N gRPC attempts (method, request summary, latency, status) for post-crash forensics; `client.mem_read(..., timeout=<seconds>)` overrides the per-call gRPC deadline |
| `sdk.nt_build` | OS build reported by the kernel view (keys `_patterns.yaml`) |

### v0.20 client primitives (agent hands/eyes/ears)

Raw `AgentClient` methods (v11 agent + ABI v10 driver for the
driver-backed ones):

```python
# Hands — send one IOCTL (gated by security.allow_ioctl_send at the MCP
# layer; the client method itself is unguarded — gate your own scripts)
res = await cl.device_ioctl("\\Device\\X", 0x222003, in_data=b"...", out_size=4096)
#   -> {ok, out: bytes, bytes_returned, last_error (Win32 gle)}

# Eyes — object namespace + threads
res = await cl.obj_enum("\\Device", depth=1, max_entries=4096)
res = await cl.thread_list(pid=4, kernel=True)   # win32_start_va/teb on v11 drivers

# Ears — target-originated events
res = await cl.events_poll(since_seq=0, max_events=256)
res = await cl.events_stats()          # buffered/dropped/seq + registered classes
stream = cl.events_stream(kinds_mask=3)  # async iterator of chunks (caller owns it)
res = await cl.events_disable()        # unregister kernel notify callbacks
```

Every mem primitive takes `view=""` (kernel) or `view="user"` — the usermode
view answers through OpenProcess-family APIs only; access-denied on protected
targets surfaces as an error instead of a crash. Kernel-only ops (`kernel=`,
kernel modules) are rejected by the usermode view by design.

### Pure helpers

```python
from suspex.sdk import Reader, buffer_reader, pattern_scan, parse_mask, parse_pe, rva_to_offset

r = buffer_reader(image_bytes)                  # or Reader(sdk.mem.read)
sig = await r.u32(base + 0x3C)                  # u8/u16/u32/u64
name = await r.wstr(ustr + 8)                   # cstr/wstr, NUL-terminated

pat, mask = parse_mask("4D 5A ?? 00")           # IDA-style -> (bytes, mask)
offs = pattern_scan(data, pat, mask)            # local scan

info = await parse_pe(r, module_base)           # headers straight from memory
foff = rva_to_offset(rva, info.sections)
```

### Analysis layer (v0.19+)

Plugins run inside the orchestrator process, so they can import the
knife-derived static-analysis package directly — no MCP hop, no IDA:

```python
from suspex.analysis import pe, engine, driver, extract, entropy
from suspex.analysis import rop, rop_emu                 # v0.21, codegen extra

img = pe.parse(dump_bytes, layout="file")        # or "image" for dumps
view = engine.ImageView(img, base_va=live_base)  # base_va overrides the
                                                 # header base (KASLR)
an  = engine.analyze_image(view)                    # needs codegen extra
surface = driver.driver_surface(engine.ImageView(img), an)
h = engine.body_hash(fn)                          # normalized fingerprint

idx = rop.build_index(view)                       # rp++-style gadget scan
rows = rop.query(idx, category="stack_pivot")     # filter at query time
rop_emu.validate_chain(view, [g_va, 0x4141, ...])  # needs unicorn extra
```

`irp_hook_check` and `code_integrity` are the reference consumers: the
first diffs a live `_DRIVER_OBJECT` against `irp_surface` output, the
second hashes a live module image against its on-disk baseline.

## 2. The plugin contract

A plugin is a directory under `suspex0\plugins\<name>\` (the shipped pack).
Personal plugins live in `suspex0\scripts_user\<name>\` — gitignored, and a
same-named local plugin shadows the pack one:

```
plugins\
  _patterns.yaml        shared per-build pattern recipes (underscore = not a plugin)
  _example\             plugin.yaml + run.py
  sigscan\
  pidddb_scan\
  umview_diff\
  memdiff\              snapshot -> delay -> diff of a region/module (unpacking detector)
  callback_scan\        kernel callback inventory via PDB symbols (driver attribution)
  yara_mem\             YARA scan of a process module image in memory
  irp_hook_check\       live DRIVER_OBJECT dispatch vs static irp_surface
  code_integrity\       live module .text vs disk via body-hash diff
```

`plugin.yaml`:

```yaml
name: sigscan
description: "signature+mask scan across a named module"
target: kernel            # kernel|user|any: required view (run is refused if absent)
params:
  module:
    type: str             # str|int|float|bool|list|dict
    required: true
  view:
    type: str
    default: "kernel"
    enum: ["kernel", "user"]
```

`run.py` — sync or async:

```python
def run(sdk, params) -> dict:
    return {"ok": True, "severity": "info", "summary": "one line", ...}
```

Rules:
- Return a JSON-serializable dict. `severity` (info|warning|high) and
  `summary` (one line) are picked up by the auto-filing.
- Param validation (types/required/enum) runs in the MCP tool AND again in
  the runner; unknown or bad params are refused before your code starts.
- Print to stdout freely while debugging — the runner redirects it to stderr.

## 3. Running plugins

MCP (the agent surface):

```
script_manage(action="list")
script_manage(action="run", name="sigscan",
              params_json='{"module": "ntoskrnl.exe", "pattern": "4D 5A 90 00"}')
script_manage(action="history")            # findings with refs plugin:<name>
script_manage(action="history", name="sigscan")
```

Each run is executed in a subprocess (`python -m suspex.plugin_runner`) with
its own gRPC clients, so a hung/crashed plugin cannot take the MCP server
down; the runner passes the view endpoints/token via stdin (not argv). The
JSON result is auto-filed into the findings ledger as a finding
(`refs=plugin:<name>`) with the full result as evidence.

CLI (same runner):

```powershell
cd orchestrator
.\.venv\Scripts\python.exe -m suspex.plugin_runner --plugin-dir ..\plugins\sigscan `
  --params-json '{"module":"ntoskrnl.exe","pattern":"4D 5A 90 00"}'
```

(offline plugins need no stdin; otherwise pipe
`{"views": {"kernel": {"host": "127.0.0.1", "port": 50099, "token": "..."}}}`.)

## 4. Kernel symbols: PDB first, patterns as fallback

`pidddb_scan` targets *unexported* globals (`PiDDBCacheTable`,
`MmUnloadedDrivers`). Two resolution paths, tried in this order:

1. **PDB (primary)** — the public symbol stream of the PDB Microsoft
   publishes for the exact build contains these names. `sdk.symbols.resolve(
   binary_path, ["PiDDBCacheTable"])` reads the RSDS GUID/age from the
   binary's debug directory, downloads the PDB on first use (urllib, no
   symsrv.dll needed) into `artifacts.pdb_cache` in standard symsrv layout,
   and resolves RVAs via dbghelp (`SymLoadModuleExW`/`SymFromNameW`,
   ctypes). `RVA + module base` = the global's kernel address.
   - The binary must exist locally: for a local target pass the System32
     path; for a remote VM pull the file first (`file_manage download`) and
     pass `binary_path`.
   - Downloads honor `symbols.allow_download: false` in config (then only
     cached PDBs are used).
2. **Pattern recipes** (offline fallback) — `_patterns.yaml` keyed by
   NtBuild; only runs when `verified: true` and a pattern is set.

PDBs give symbol *addresses*, not struct layouts: the `walk` offsets
(UNICODE_STRING position inside `PI_DDB_CACHE_ENTRY` etc.) stay per-build
in `_patterns.yaml`. Purpose remains unload-hygiene verification of OUR OWN
drivers against the driver's op log — not stealth.

To land a pattern recipe for a build where PDB resolution is unavailable:
1. Pull the exact signed binary of that build (`ci.dll` / `ntoskrnl.exe`).
2. Locate the symbol in IDA — for a big driver use `ida_manage
   action=open_async` (returns pending in ~5s; poll `open_status` or
   `list`) instead of the blocking `open`; then `action=get_function_by_name`
   or `action=list_globals_filter` via passthrough. When `ghidra.enabled`
   is configured, `ghidra_manage` is a drop-in alternative with the same
   verb surface (open/open_async/open_status/passthrough) — useful as a
   second decompiler opinion or when idalib isn't licensed on the box.
3. Pick a unique byte pattern in code/data referencing the global; write
   `pattern`/`mask` + the walk offsets; set `verified: true`.
4. Run `script_manage run name=pidddb_scan` — a no-match result files a
   `warning` finding so stale recipes are visible.

## 5. Writing your own

1. `mkdir plugins\my_thing` (or `scripts_user\my_thing` for a local-only
   plugin), copy `_example\plugin.yaml`, edit name + params schema.
2. Write `run.py` with `def run(sdk, params)`; use `sdk.mem/mods/procs/dbg/
   findings`; keep results structured and file evidence for anything
   worth remembering.
3. `script_manage(action="list")` should show it; run it; iterate.
4. Add tests in `orchestrator\tests\` following `test_plugins.py` (offline
   subprocess runs, param validation).

## 6. Pitfalls (learned the hard way)

These are the traps a long research engagement flagged; keep the list in
mind when writing plugins or driving the MCP surface directly.

- **`space=` is canonical for `pattern_scan`; `kernel=true` is a legacy
  alias.** `space=user|kernel|physical` selects the memory space. If both
  disagree the code path currently believes `space=` — a mismatch is a
  silent bug source, not an error.
- **`address` and `base` are interchangeable on `pattern_scan`; ranges need
  `size`.** A whole-space scan is `address=0, base=0, size=0`; anything
  else needs the range explicitly and returns `bytes_scanned` /
  `chunks_skipped` telemetry. A negative result with `chunks_skipped>0`
  is "the range was mostly unreadable", not "the pattern isn't there".
- **`allow_fault=false` is the safe default for kernel probes.** The
  driver's soft-fault fallback (`MmCopyMemory` -> `RtlCopyMemory` inside
  `__try/__except`) bugchecked the target on unresolvable page faults —
  SEH doesn't catch KM page faults. Blind pointer probing must run with
  `allow_fault=off`; you get a clean `INVALID_ADDRESS` on bad VAs.
- **Physical memory access (v4 rework, 2026-09-06).** The v1 path
  called `MmMapIoSpace(MmNonCached)` which returns NULL for normal
  RAM on Win 26200+ (only firmware-reserved / MMIO accept the
  non-cached IO map) — every physical read failed `gle=1450`. v4
  primary path is `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)` and the
  fallback is `MmMapIoSpaceEx(MmCached)`; the RAM-range check is
  re-queried per call so hotplug is reflected. Physical census works
  again. Requires the v4 driver — `SUSPEX_ABI_VERSION` bump gates this.
- **Kernel pool inspection is now available** via `mem_rw pool_scan`
  (backed by `SystemBigPoolInformation` + `MmCopyMemory` for content
  filtering). Only >4 KB "big pool" allocations show up — small pool
  is opaque on modern Windows (segment heap) and we do not fake data
  we cannot get.
- **Concurrency envelope for driver-backed IO is now enforced.** Phase
  A landed a per-view semaphore that caps in-flight driver-backed gRPC
  calls at 16 (config-tunable via `targets.<name>.max_inflight`);
  excess calls queue rather than pile into the driver. Serialized
  `PAR=1` sweeps of 1500 candidates and `PAR=16` sweeps of 7800 worked
  under the old regime; wider parallelism previously coincided with a
  target crash under the soft-fault bug, so the cap defaults
  conservatively. Raise it deliberately if you know the workload.
- **`pattern_scan` chunks skip on read failures — but count them.** The
  loop realigns to the next page and continues; the returned
  `chunks_skipped` says how many holes were hit. Don't treat `[]` as
  "not present" without checking `bytes_scanned` first.
- **IDA `open` blocks up to the MCP request deadline; `open_async`
  doesn't.** For any binary over ~30 MB use `open_async` + `open_status`
  from the start. Pass `run_auto_analysis=false` when you want to carve
  functions by hand (`create_function` on specific eas, then run
  `auto_wait` via `exec_idapython`).
- **Session id vs friendly name.** The bridge keys sessions by the
  friendly `name` (usually `Path(path).stem`); the shim keys them by the
  same string in the common case but accepts `database=` on
  `idb_close`/tool passthrough. If you resolve manually, use `ida_manage
  list` — the response maps name → session_id explicitly.
- **Never call `save_database(<input_path>)`** — silently overwrites the
  input .sys with packed IDA2 bytes and destroys it. Real bug hit during
  the nvlddmkm engagement (a hook lost a .sys mid-analysis this way).
  The v0.7 extension entry now guards `idapro.save_database`
  **process-wide**: any target equal to the input, lacking a database
  extension, or empty is redirected to `<input>.i64` (logged as
  `[suspx-guard]` in the backend log); a hard refusal only happens when
  no input path was ever recorded. `idb_save` remains the recommended
  checkpoint tool (it also refuses saves mid-segment-change).
- **Read `ida_status` before assuming an open succeeded.** `idb_open`
  returning "success" covers three real cases: analysis done, analysis
  still running, and analysis done but the startup hook failed
  (NameError in the extension). `ida_status` distinguishes them
  (`analysis_state`, `functions_count`, `state_code`); `ida_log`
  returns the backend log tail for hook tracebacks.
- **Empty tool responses are ambiguous.** `get_xrefs_to(addr) == []`
  could mean (a) addr not in DB, (b) region not yet analysed, (c) truly
  no xrefs, (d) backend just died. Resolve on demand with one
  `ida_manage` action `ctx` (`ida_query_context`,
  `args_json={"address":"0x..."}`): it returns `addr_in_db`,
  `in_function`/`function_start`, and `analysis_state` in a single
  round trip — (a) `addr_in_db:false`, (b) `analysis_state:"running"`,
  (c) `analysis_state:"idle"` with a mapped address, (d) the call
  itself fails at the shim with a transport error naming the session.
  Keep using `ida_status` for whole-session snapshots and `ida_log`
  when the backend feels off.
- **`mem_rw read size > 4 MiB`** auto-uses the v5 streaming path
  (`Memory.ReadStream`). Response gains `stream: true`. If the target
  is a v4 agent the call rejects with "agent < v5" instead of the old
  hard-cap error.
- **Big IDA outputs are auto-jobbed (v0.8+).** A `decompile_function`
  on a 100 KB routine used to crash the bridge's `readline()` with
  `ValueError: Separator is found, but chunk is longer than limit`;
  a `disassemble_function` on a huge routine hit MCP -32001. Both are
  now transparent: any passthrough call exceeding
  `SUSPX_IDA_JOB_SOFT_DEADLINE_S` (default 25s) or returning more
  than `SUSPX_IDA_JOB_CHUNK_BYTES` (default 24 KiB) is stashed in
  a JOBS cache and the caller gets a small `{__suspex_pending, ...}`
  or `{__suspex_chunked, ...}` envelope with a `job_id`. Poll
  `ida_manage(action="job_status", args_json='{"job_id":"..."}')` and
  fetch pages via `action="result"` — concatenate `data` across pages
  `0..total_pages-1`. Explicit start: `action="job_start"` with
  `tool="..."` for cases you know up-front will run long.
