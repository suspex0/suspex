# ReverseKit review — enhancements for suspex0

Source: https://github.com/zer0condition/ReverseKit (C++, ImGui, MIT).
Purpose: dynamic RE toolkit that lives inside a target process. Surface = a DLL
injected via `ReverseKitLoader` that renders an ImGui window over a DX9 hook
and exposes runtime introspection + a few defensive hooks.

This doc triages every ReverseKit subsystem against the current suspex0 tool
surface (`proto/suspex.proto`, MCP tools in
`orchestrator/src/suspex/mcp/tools.py`, driver ABI in `comm/suspex_abi.h`)
and lists what is worth adopting, what is redundant, and where the current
line sits.

**Scope note (2026-09-05).** The prior blanket "no stealth/evasion" ban has
been lifted for *target-facing* work: dynamic analysis of malware and
anti-debug samples is impossible without spoofing what the target sees.
suspex0 may now install debugger-probe spoofs, syscall-callback tracers,
and API-hook observers **inside the sample under study**. What stays banned
is anything that mutates the analyst's own defensive posture (host AV/EDR,
HVCI, PatchGuard).

---

## 1. Feature triage

| ReverseKit subsystem | File | Verdict | Notes |
|---|---|---|---|
| DX9/ImGui overlay + menu | `Window/`, `Menu/`, `ImGui/` | **Skip** | Suspex0 is headless with a WS dashboard + MCP; an in-target GUI is off-model. |
| DLL loader / injector | `ReverseKitLoader/` | **Skip** | We have `mapper.exe` (manual map) and the SCM service path; injection strategy is not a gap. |
| IAT walker (`GetImportsFromIAT`) | `Imports/Imports.cpp` | **Adopt** | Suspex0 lists modules but never surfaces IAT/EAT of a live target. |
| Heap enumeration (Toolhelp) | `Heaps/Heaps.cpp` | **Adopt** | We expose VAD + handles but not per-heap block layout. |
| Thread enumeration + CPU% | `Threads/Threads.cpp` | **Adopt (extend)** | Debug.GetThreads returns tid/teb/suspend_count/start_addr; adding times/CPU is trivial. |
| Instrumentation callback tracer | `Instrumentation/*` + `Thunk.asm` | **Adopt (flagship)** | Register `ProcessInstrumentationCallback` (info class 0x28) to trap syscall returns per-thread. Powerful observation primitive, no evasion angle. |
| Trampoline / JMP hook engine | `ReverseLib/ReverseHook.cpp` | **Adopt** | Building block for the target-side spoofs, the tracer thunk, and future observation shims. Now that target-facing hooks are in scope, this can also back an SDK-exposed `hook` primitive (§F). |
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` spoof | `Hooks/SetHooks.cpp` | **Adopt (§F)** | Standard anti-anti-debug. Required to observe samples that gate on debugger probes. |
| `NtQueryInformationProcess(ProcessDebugPort/Flags/ObjectHandle)` spoof | not in ReverseKit — adjacent | **Adopt (§F)** | Same rationale; ReverseKit misses the syscall-level variants that real malware uses. Add while we're building the spoof surface. |
| `RtlAdjustPrivilege` filter | `Hooks/SetHooks.cpp` | **Adopt as observer + optional block (§F)** | Reframed: observe by default, block on scenario opt-in when analyzing samples that self-terminate/BSOD as an anti-analysis reflex. |
| Sysmon-unload filter / `wevtutil cl Setup` filter | `Hooks/SetHooks.cpp` | **Adopt as evidence-preservation observer (§F)** | Malware that scrubs telemetry is exactly what we want to observe. Default = observe + log; scenario-scoped opt-in can also refuse the call. Never enabled globally. |
| URL-download interception | inside SetHooks (`URLDownloadToFileA`, `InternetOpenUrlW`) | **Adopt as observer (§F)** | Network-IOC telemetry. Observer by default; scenario opt-in can rewrite target of the download for controlled fetch. |
| `CreateProcessInternalW`, `NtCreateThreadEx` observers | `Hooks/SetHooks.cpp` | **Adopt as observer (§F)** | Child-process / injected-thread telemetry — pairs well with the syscall tracer (§C). |

Already-present in suspex0 (no work needed):
- module enumeration (`mem_rw modules`), process enumeration
  (`mem_rw process_list`), VAD, handles, region walks, pattern scan
- thread enumeration and stacktrace via DbgEng (`debug_manage threads` / `stacktrace`)
- IAT parsing statically via IDA (`ida_manage`) once a binary is dumped

---

## 2. What still stays out of scope (analyst-side, not target-side)

The 2026-09-05 policy shift only touches what happens **inside the target
process**. The analyst's own host is still governed by hard limits:

- No patching or disabling of the analyst's PatchGuard, HVCI, DSE, or
  Secure Boot. If a scenario needs them off, the *user* toggles them on
  the lab VM — the agent does not.
- No suppression or bypass of the analyst-host AV/EDR. The kernel driver
  is test-signed and lives at `\\.\SuspexDrv`; it never hides itself from
  the analyst's own EDR (that's what the op-log at
  `C:\Users\Public\Desktop\suspex_kernel.log` is for — visible ground truth).
- No PatchGuard-unsafe kernel `.text` writes on the analyst's kernel.
  Kernel breakpoints stay DR0-3/context-based unless testsigning + PG
  defanging is explicitly on for the lab VM.
- Target-side hooks that *block* rather than *observe* (e.g., refuse a
  `wevtutil cl` call so the sample's cleanup fails) are opt-in per
  scenario and default OFF, because a hostile sample changing behavior
  when its cleanup fails is itself an observation to be aware of.

The distinction is: spoofing what a **sample** sees is analysis; spoofing
what a **defender** on the analyst's box sees is out of scope.

---

## 3. Enhancements to adopt — mapping to suspex0

### A. Live IAT / EAT enumeration (small, high value)

**Motivation.** IDA (`ida_manage`) parses imports statically on a dumped
image. It cannot see the *resolved* pointer values at runtime, which is
exactly what tells you whether an IAT has been hooked, whether an ordinal
resolves to the DLL you expect, or which forwards were followed. That is the
gap ReverseKit's `Imports/Imports.cpp` fills for the local process; we want
it for any pid, over the existing gRPC channel.

**Wire (`proto/suspex.proto`, Memory service).**

```proto
message IatEntry {
  string dll = 1;        // as it appears in the descriptor
  string name = 2;       // export name, or empty when imported by ordinal
  uint32 ordinal = 3;    // valid iff name == "" and IMAGE_ORDINAL_FLAG was set
  uint64 iat_slot = 4;   // VA of the FirstThunk slot in the caller image
  uint64 resolved = 5;   // pointer currently in the slot
  string resolved_module = 6; // module that owns `resolved`, or empty if none
  string resolved_symbol  = 7; // best-effort symbol at `resolved`, or empty
  bool hooked = 8;       // true iff resolved_module != declared dll (heuristic)
}
message ModuleImportsRequest {
  uint32 pid = 1;        // 0 => kernel module (walk kernel view)
  string module = 2;     // basename or full path
  bool kernel = 3;
}
message ModuleImportsResponse {
  OpStatus status = 1;
  repeated IatEntry entries = 2;
}
message ExportEntry {
  string name = 1;
  uint32 ordinal = 2;
  uint64 rva = 3;
  uint64 address = 4;         // base + rva
  string forwarder = 5;       // e.g. "api-ms-...!Foo"; empty for regular exports
}
message ModuleExportsRequest { uint32 pid = 1; string module = 2; bool kernel = 3; }
message ModuleExportsResponse { OpStatus status = 1; repeated ExportEntry entries = 2; }
```

Add both as RPCs on `service Memory` (they are pure reads).

**Agent (`agent/src/`).** New file `agent/src/pe/pe_reader.{hpp,cpp}` — a
build-independent PE walker that takes a `read(addr,size)` callable so it can
be reused for both usermode (`ReadProcessMemory` view) and kernel
(`SuspxUserMemRead`/`SuspxKernelMemRead`). Wire it into `services.cpp`
alongside `Modules`.

**Driver.** No new IOCTL — we already have all reads. Just resolve the
module base via the existing `SuspxUserModules`/`SuspxKernelModules` walk.

**Orchestrator + SDK.**
- Extend `mem_rw` tool with two new actions: `imports` (params `pid`,
  `module`, `kernel`) and `exports` (same).
- `sdk.py`: `sdk.mods.imports(pid, module, *, view="")` and
  `.exports(...)` returning typed dataclasses. `parse_pe` already exists;
  reuse it for header math on the local reader too.
- A ready-made script under `plugins/iat_diff/` that flags entries
  where `resolved_module != declared dll` — the "who hooked my IAT" plugin.

**Cost.** ~1 day. Small proto change, one new C++ file, one MCP action, one
SDK entry point, one plugin, unit tests. No driver work.

### B. Heap layout enumeration

**Motivation.** VAD tells us reservations and protections; heaps tell us
allocation shape. ReverseKit does this for its host process only; we need it
for any pid.

**Design decision.** ReverseKit's `Toolhelp32` path only works for the
current process. For arbitrary pids we walk the target's heaps from its
PEB — `PEB->NumberOfHeaps`/`ProcessHeaps` gives an array of `HEAP*`, and
each `HEAP` has segment/entry chains. Layouts move across builds, so
implement it in agent usermode (via `ReadProcessMemory`) with a small
`heap_layout.yaml` recipe keyed by NT build (same pattern as
`plugins/_patterns.yaml`). No kernel work required for v1; if elevation
denies handle open, surface the asymmetry via OpStatus.

**Wire.**

```proto
message HeapBlock { uint64 address = 1; uint64 size = 2; uint32 flags = 3; }
message HeapEntry {
  uint64 handle = 1;       // HEAP*
  uint32 flags = 2;
  uint64 base = 3;
  uint64 committed = 4;
  uint64 reserved = 5;
  repeated HeapBlock blocks = 6; // populated when want_blocks
}
message HeapListRequest { uint32 pid = 1; bool want_blocks = 2; uint32 max_blocks = 3; }
message HeapListResponse { OpStatus status = 1; repeated HeapEntry heaps = 2; }
```

Add `rpc HeapList(HeapListRequest) returns (HeapListResponse)` to `Memory`.

**MCP.** Extend `mem_rw` with `heaps` (params `pid`, `want_blocks`,
`max_blocks`).

**SDK.** `sdk.mem.heaps(pid, want_blocks=False)`.

**Cost.** ~1 day. All in agent + orchestrator + SDK. Add a plugin
`plugins/heap_hunt/` that greps blocks for a byte pattern to reuse the
existing scan primitives.

### C. Instrumentation-callback syscall tracer (flagship)

**Motivation.** ReverseKit registers a `ProcessInstrumentationCallback`
(`NtSetInformationProcess`, info class 0x28) plus a thunk that catches
control right after each syscall returns to usermode. It's the cheapest and
least-invasive syscall trace primitive on Windows — no kernel patching, no
ETW filtering, no PatchGuard risk. For a pentester's LLM this is a step
change: "attach to pid X and stream every syscall" becomes a single tool
call.

**Where it fits.** suspex0 already has the pieces to install it cleanly:

- `driver/src/RemoteCall.c` already ferries code into a target via a
  kernel-initiated user APC — that's the injector for the thunk stub.
- `driver/src/Context.c` already sets thread context via the driver — that's
  what applies the callback pointer, on all threads or specific ones.
- The gRPC event streaming pattern is already in `Debug.StreamEvents`.

**Design.**

1. Build the thunk stub (a hand-written x64 `.asm`, one page, position
   independent) that saves the interrupted context and writes a
   fixed-format record into a ring buffer allocated in the target with
   `Memory.Alloc`. The record is `{ tid, rip, syscall_ret_rax, r10, timestamp }`.
   Model the prologue on `ReverseKit/Instrumentation/Thunk.asm` (TEB slots
   `0x2d8`/`0x2e0`, `RtlCaptureContext`, 32-byte shadow space).
2. Allocate the ring in the target as RWX (`Memory.Alloc`), stamp the stub
   into it, then call `NtSetInformationProcess(handle, 0x28, &cb, sizeof)`.
   The `handle` comes from an open-with-`PROCESS_SET_INFORMATION`, opened
   inside the agent under `SeDebugPrivilege`; if that fails (PPL), fall
   back to a driver-side `ZwSetInformationProcess` (well-known kernel
   surface; add IOCTL if elevation is short).
3. Agent thread `mmap`s the ring's kernel view (via
   `SuspxUserMemRead`) and pumps records into a new gRPC stream.

**Wire.** New service:

```proto
message SyscallStartRequest {
  uint32 pid = 1;
  uint32 ring_bytes = 2;     // default 1 MiB
  repeated string dll_filter = 3;   // e.g. ["ntdll", "win32u"] for RIP filtering
}
message SyscallStartResponse {
  OpStatus status = 1;
  uint32 session_id = 2;
  uint64 ring_base = 3;      // for debugging
}
message SyscallEvent {
  uint64 seq = 1;
  uint32 tid = 2;
  uint64 rip = 3;            // return address inside caller (post-syscall)
  string module = 4;
  string symbol = 5;         // best-effort resolve
  uint64 rax = 6;            // syscall return value (NTSTATUS for Nt* / Zw*)
  uint64 timestamp_100ns = 7;
}
message SyscallStopRequest { uint32 session_id = 1; }
message SyscallStreamRequest { uint32 session_id = 1; uint64 from_seq = 2; }

service Syscalls {
  rpc Start(SyscallStartRequest) returns (SyscallStartResponse);
  rpc Stop(SyscallStopRequest)   returns (OpStatus);
  rpc Stream(SyscallStreamRequest) returns (stream SyscallEvent);
}
```

**MCP.** New consolidated tool `trace_manage` (`action=start|stop|stream|list`).
Tool call is destructive-flagged because installing the callback modifies a
foreign process. Config-gated:
`configs/example.yaml` adds `trace.enabled: false` and
`trace.max_ring_bytes: 4194304`.

**SDK.** `sdk.trace.start(pid, ring_bytes=...)`,
`.stop(session_id)`, `async for ev in .stream(session_id, from_seq=0)`.

**Cost.** ~3–5 days including the stub, the ring pump, symbol resolution
reuse (`suspex.symbols`), and integration tests against a
built-in-callback-friendly target (`ping`, `notepad`). Requires HVCI to be
off if we go through the manual-map path; the driver path (option 2b
above) works with HVCI on. Add a `sysinfo` warning if the caller asks to
start on HVCI without the driver path available.

**Safety line to keep.** The tracer never *changes* syscall args or return
values. Callback is post-syscall, observational only. If the user ever asks
for "spoof this return", refuse — that is stealth, not observation.

### D. Thread CPU/timing metrics (5-line change)

Extend `ThreadInfo` in `proto/suspex.proto` with `create_100ns`,
`exit_100ns`, `kernel_100ns`, `user_100ns`. Populate in
`agent/src/dbg/dbg_session.cpp::GetThreads` from `GetThreadTimes(hThread,
...)` on the DbgEng thread handle we already own. Surface in
`debug_manage threads`. Zero risk.

**Cost.** ~1 hour.

### E. Trampoline hook engine — now SDK-exposed

`ReverseHook::hook`/`Trampoline::hook` (14-byte `mov rax, imm64; jmp rax`
prologue swap) lands as `agent/src/pe/hook_prologue.{hpp,cpp}`. Under the
new scope it also backs an SDK primitive:

```python
# from a plugin
h = await sdk.hook.install(pid=vic, target="ntdll!NtOpenFile",
                           stub="observe",  # or "spoof", "block"
                           spoof={"return": 0xC0000022})  # STATUS_ACCESS_DENIED
async for ev in sdk.hook.stream(h):
    findings.record(...)
await sdk.hook.remove(h)
```

Wire additions (new `Hooks` service, register in `services.cpp`):

```proto
enum HookMode { OBSERVE = 0; SPOOF = 1; BLOCK = 2; }
message HookInstallRequest {
  uint32 pid = 1;
  uint64 target = 2;         // absolute VA in target
  string target_symbol = 3;  // optional, resolved server-side for the record
  HookMode mode = 4;
  bytes stub_config = 5;     // spoof: {return, argc, arg_overrides}; observe: filter
}
message HookInstallResponse { OpStatus status = 1; uint32 hook_id = 2; }
message HookEvent {
  uint64 seq = 1;
  uint32 tid = 2;
  repeated uint64 args = 3;      // captured on entry (up to 8)
  uint64 return_value = 4;       // on return, or synthesized under SPOOF/BLOCK
  bool spoofed = 5;
}
message HookRemoveRequest { uint32 hook_id = 1; }
message HookStreamRequest { uint32 hook_id = 1; uint64 from_seq = 2; }
service Hooks {
  rpc Install(HookInstallRequest) returns (HookInstallResponse);
  rpc Remove (HookRemoveRequest)  returns (OpStatus);
  rpc Stream (HookStreamRequest)  returns (stream HookEvent);
}
```

MCP: `hook_manage` (`action=install|remove|list|stream`), destructive-flagged.
Safety: install goes through the driver's kernel-APC delivery
([RemoteCall.c](../driver/src/RemoteCall.c)) so the target sees a
consistent write; every install is recorded to
`C:\Users\Public\Desktop\suspex_kernel.log` so the analyst always has a
ground-truth record of what was patched into which pid.

### F. Target-facing anti-anti-analysis suite

The point of the policy shift. A single new plugin `plugins/decloak/`
plus a `decloak_manage` MCP action that installs a curated pack of hooks
via §E. Pack contents:

- `debugger_probes`: return `FALSE` from `kernel32!IsDebuggerPresent` and
  `CheckRemoteDebuggerPresent`; zero out `PEB->BeingDebugged` and
  `PEB->NtGlobalFlag & 0x70` for the target; return
  `STATUS_PORT_NOT_SET`/zero for `NtQueryInformationProcess` classes
  `ProcessDebugPort` (7), `ProcessDebugObjectHandle` (30),
  `ProcessDebugFlags` (31). This is the classic anti-anti-debug package;
  ReverseKit only covers the first two APIs, we need the syscall variants.
- `timing_smooth`: intercept `NtQueryPerformanceCounter` and
  `RtlGetTickCount` to normalize the delta the target sees across
  breakpoints (defeats "we were suspended too long" checks).
- `hardware_hints`: hook `NtQuerySystemInformation` classes that leak VM
  hints (SMBios, firmware) to return non-VM values on scenario opt-in.
- `evidence_preservation`: observers on `RegDeleteKey*`, `DeleteFile*`,
  `NtSetSystemInformation(SystemUnloadGdiDriverInformation)`,
  `EvtClearLog`, `sc unload SysmonDrv` shell-scan — all default OBSERVE;
  scenario config can flip individual ones to BLOCK.
- `network_ioc`: observers on `URLDownloadToFileW`, `InternetOpenUrlW`,
  `HttpSendRequestW`, `WinHttpSendRequest`, `WSAConnect` — for IOC
  extraction into the findings ledger.
- `child_processes`: observers on `NtCreateUserProcess` and
  `NtCreateThreadEx` (cross-process) with argument capture; useful for
  spawn-and-inject sequences.

Pack config lives in `plugins/decloak/pack.yaml`. Each entry names
the target symbol, the mode, and the finding category it emits.

**Cost.** ~2–3 days after §C/§E land, mostly plumbing + scenario testing
against a known-anti-debug sample (e.g., a locally built test that gates
on all six debugger probes).

---

## 4. Rollout order and validation

Sequence chosen so each layer is validated before the next builds on it:

1. **§D thread metrics** (1 hour). Adds no attack surface. Regression check
   is the existing threads test in `orchestrator/tests/`.
2. **§A IAT/EAT walker** (1 day). Ships behind `mem_rw imports/exports` and
   a new plugin `iat_diff/`. Validation: dump `notepad.exe`, compare live
   IAT vs the same IAT via `ida_manage` on the dumped file — must agree
   on every ordinal/name and disagree only on `resolved` (live) vs
   `iat_slot`'s file value.
3. **§B heap enumeration** (1 day). Validation: same-process heap walk
   matches `_CrtDbgReport`-style output; cross-process walk of a spawned
   `ping` matches PEB-parsed data. Add pytest that mocks the reader.
4. **§C syscall tracer** (3–5 days). Validation:
   - unit tests for stub assembly (disassemble the emitted bytes, check
     TEB offsets),
   - integration test that launches `cmd /c ping -n 5 127.0.0.1`, attaches,
     asserts at least one `NtDelayExecution` return event per second,
   - HVCI-on rerun on the lab VM through the driver path,
   - kernel-log audit (`C:\Users\Public\Desktop\suspex_kernel.log`) shows
     the `ProcessInstrumentationCallback` set and clear on teardown.
5. **§E hook engine + SDK surface** (2 days). Validation: install an
   OBSERVE hook on `ntdll!NtOpenFile` in a spawned `cmd /c dir`, assert
   captured args match a parallel Sysmon trace on the lab VM; assert
   SPOOF mode returns `STATUS_ACCESS_DENIED` and the target sees it;
   assert BLOCK short-circuits without calling the original prologue.
   Verify hook removal restores the original 14 bytes byte-for-byte.
6. **§F decloak pack** (2–3 days). Validation on a purpose-built test
   binary that checks all six debugger probes plus a
   `QueryPerformanceCounter` timing gate — with the pack installed the
   binary should report "no debugger, timing normal"; without it the
   binary should exit with the anti-debug branch flag set. Also run
   against a known open-source malware sample (e.g. an EICAR-like
   PoC written for the lab) to confirm end-to-end behavior extraction.

Every phase updates [docs/E2E_SCENARIO.md](E2E_SCENARIO.md) with the new
tool calls and lands the changes on `main` (the `PLAN_NEXT.md` handoff doc
was retired; the canonical state now lives in README.md + this doc set +
git history) so a future session can pick up the state.

## 5. Non-adoption checklist (record so we don't drift)

- No target-side hook is installed **without** logging the install/remove
  to the kernel op-log at
  `C:\Users\Public\Desktop\suspex_kernel.log` — analyst always sees ground truth.
- No modification of the analyst's own kernel/security stack (PatchGuard,
  HVCI, DSE, Secure Boot, host AV/EDR).
- No DX9/ImGui overlay inside targets.
- No injector — the manual-mapper and SCM service cover our needs.
- BLOCK-mode entries in the decloak pack default OFF; they are opt-in per
  scenario and each BLOCK install emits a distinct finding so it shows up
  in reports.

## 6. Attribution

ReverseKit is MIT-licensed. Any code we port keeps the ReverseKit copyright
alongside our own header. Adopted files must carry a note pointing at the
upstream file and commit, e.g.:

```
// Portions adapted from ReverseKit (MIT), zer0condition/ReverseKit
//   <upstream file>@<commit sha>
```
