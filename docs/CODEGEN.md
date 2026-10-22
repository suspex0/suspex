# Codegen / emulate — analyst walkthrough

Delivered by [.kilo/plans/2026-09-11-codegen-craft-emulate.md](../.kilo/plans/2026-09-11-codegen-craft-emulate.md).
Three capabilities layered so analysis never has to touch the target
just to ask "what do these bytes do":

1. **Disassemble / assemble on demand** — read bytes at a target VA and
   decode them; hand-write a snippet and get bytes back. All local; no
   round trip to IDA for `what does this shellcode do?`.
2. **Emulate off-target** — take assembled bytes (or bytes read from a
   live target), run them in a Windows-veneered Speakeasy VM (or bare
   Unicorn), watch the API-call log + final registers, single-step.
   Answers "will this decoder produce the right plaintext?" without
   ever touching the target.
3. **Seed the emulator from live target state** — pull registers and
   memory regions off the target, hydrate the emulator with them, and
   step from exactly the CPU state the real thread saw. "Why is this
   branch taken?" without live debug.

> **Withdrawn: Windows Sandbox (Phase 3).** The `.wsb` / `run_sandbox`
> surface shipped briefly in v0.13.0 and was removed in v0.13.1 —
> Windows Sandbox inside a nested VM proved unstable in live testing
> (instant `0xC0000142` fast-fails, multi-minute boots, and eventually
> a hard guest crash). For real-machine execution use a disposable VM
> with snapshot rollback; everything code-level is covered by
> `emulate_manage`.

## Install

Everything under `mem_rw disasm/assemble` and `emulate_manage` needs the
`codegen` extra:

```bash
pip install 'suspex0[codegen]'
# or: uv sync --extra codegen
```

That pulls capstone, keystone-engine, unicorn, and speakeasy-emulator.
The core stack works without it — the tool actions raise a named
`codegen_extra_missing` error on first call.

## Phase 1 — disasm / assemble

`mem_rw` learned two new actions. Both accept a raw hex buffer for
pure-compute or an `address=` for target-read.

Disassemble bytes:

```json
{
  "tool": "mem_rw",
  "arguments": {
    "action": "disasm",
    "bytes_hex": "4889e5c3",
    "arch": "x64",
    "syntax": "intel",
    "address": "0x140001000"
  }
}
```

Response carries per-instruction `{addr, bytes, mnemonic, op_str, size, sym}`.
`resolve_symbols=true` annotates operand constants that resolve inside a
loaded module as `module+offset`, in the same shape `mem_rw resolve`
already accepts.

Disassemble the target's memory at a live VA:

```json
{
  "tool": "mem_rw",
  "arguments": {
    "action": "disasm",
    "address": "0x140012340",
    "size": 256,
    "space": "user",
    "pid": 1234,
    "resolve_symbols": true
  }
}
```

Uses the v6 partial-read path — an unmapped page produces a `truncated:
true` + `first_bad_offset` response, not a full failure.

Assemble a snippet (pure-compute; no target contact):

```json
{
  "tool": "mem_rw",
  "arguments": {
    "action": "assemble",
    "code": "mov rax, 1; syscall",
    "arch": "x64",
    "address": "0x140001000"
  }
}
```

Response includes `bytes_hex`, `size`, `ins_count`, `roundtrip`
(auto-disasm of what was assembled), and `labels` when any bare
`name:` markers resolve.

Write assembled bytes back to the target (destructive; must set
`dry_run=false` explicitly, or the tool refuses with `unsafe_default`):

```json
{
  "tool": "mem_rw",
  "arguments": {
    "action": "assemble",
    "code": "int3; ret",
    "write_to": "0x140001500",
    "space": "user",
    "pid": 1234,
    "dry_run": false
  }
}
```

## Phase 2 — emulator sessions

`emulate_manage` creates and drives emulator sessions. The lifecycle
mirrors `ida_manage`:

```json
{"tool": "emulate_manage", "arguments": {"action": "create", "arch": "x64", "engine": "unicorn"}}
```

→ `{"session_id": "e0001", "engine": "unicorn", ...}`

Load bytes (or assemble on the way in), then run:

```json
{"tool": "emulate_manage", "arguments": {
  "action": "load_shellcode",
  "session_id": "e0001",
  "code": "mov rax, 1; ret"}}

{"tool": "emulate_manage", "arguments": {
  "action": "run",
  "session_id": "e0001",
  "max_ins": 1000}}
```

`run` returns `halt_reason`, `duration_s`, an `api_calls` log
(Speakeasy engine), the event ring, and the final regs snapshot.

### The bridge action — `seed_from_target`

Pull the live target's regs + selected memory regions into the emulator
so the LLM can single-step from the exact CPU state a real thread saw:

```json
{"tool": "emulate_manage", "arguments": {
  "action": "seed_from_target",
  "session_id": "e0001",
  "view": "user", "pid": 1234, "tid": 5678,
  "regions_json": "[{\"address\":\"0x7ff600000000\",\"size\":\"0x50000\",\"label\":\"image\"},{\"address\":\"0x1234abcd\",\"size\":\"0x1000\",\"label\":\"heap\"}]"}}
```

Uses the v6 partial-read path (kernel view) so unmapped pages produce
holes (reported in the response) rather than aborting the whole seed —
user-view seeding uses the plain read path. Register hydration is
best-effort and only lands when a `debug_manage` session is attached on
the target (the agent's GetRegs RPC has no thread selector).

### Engine choice

`create(engine="speakeasy")` (default) uses Mandiant's Speakeasy —
Windows-focused, fake ntdll/kernel32/user32 veneer with hookable API
stubs. Best for Windows shellcode + PE analysis.

`create(engine="unicorn")` is the escape hatch — bare Unicorn Engine,
no OS surface, no hooked APIs. Use when the Speakeasy install chain
misbehaves on your Python version or when you want pure-CPU emulation
with true single-stepping and snapshot/restore.

### API hooks (Speakeasy)

```json
{"tool": "emulate_manage", "arguments": {
  "action": "hook_add",
  "session_id": "e0001",
  "kind": "api",
  "api": "kernel32!VirtualAlloc",
  "hook_action": "return",
  "return_value": "0x1000000"}}
```

Every hook fire pushes an entry into the per-session event ring. `run`
returns the events alongside the halt reason, so a single call sees
"shellcode did GetProcAddress → VirtualAlloc(size=0x1000, protect=PAGE_EXECUTE_READWRITE)".

## Phase 4 — putting it together

The [`craft_test`](../plugins/craft_test/) reference plugin
demonstrates the full loop:

```bash
suspex script_manage run --name craft_test --params '{
  "code": "mov rdi, 0x2000; mov rcx, 32; loop: xor byte ptr [rdi], 0xAA; inc rdi; dec rcx; jnz loop; ret",
  "arch": "x64",
  "entry": 4096,
  "emulate": true,
  "emu_engine": "unicorn"
}'
```

Assembles the source, disassembles the bytes back for a round-trip
check, spins up the emulator, runs to halt, dumps the final regs.

The plugin is intentionally short — copy it and adapt for whatever
lightweight assemble → verify → emulate loop your analysis needs.

## When to use which

| You want to... | Reach for |
|---|---|
| Know what these bytes at VA `0x…` do | `mem_rw disasm(address=…)` |
| Hand-craft a payload | `mem_rw assemble(code=…, dry_run=true)` |
| Round-trip verify assembly is correct | assemble → disasm on the returned `bytes_hex` |
| Test a decoder / stub off-target | `emulate_manage create/load_shellcode/run` |
| See which APIs an obfuscated shellcode resolves | Speakeasy engine + `hook_add(kind="api")` |
| Replay a live thread's state | `emulate_manage seed_from_target` |
| Write a plugin that chains all of the above | copy `plugins/craft_test/` |
| Test under a real Windows kernel | disposable VM with snapshot rollback (external to this stack) |

## Known limitations

- **Speakeasy install fragility.** The `speakeasy-emulator` PyPI wheel
  (2.0.0b6 at time of writing) has API churn — the wrapper passes shellcode
  via `data=` and reads registers through `get_all_registers()` (values are
  hex strings). When Speakeasy fails to initialize, fall back to
  `engine="unicorn"` — you lose the Windows API veneer but keep the bare
  CPU + snapshots.
- **Snapshot on Speakeasy.** Not wired yet. Use the Unicorn engine
  when you need snapshot / restore.
- **Stepping on Speakeasy.** 2.x `run_shellcode` takes no instruction
  cap, so `step` runs to the natural halt (the response carries a `note`).
  Use the Unicorn engine for true single-stepping.
- **PE loader on Unicorn.** Not wired — the plan defers this pending
  concrete demand. `emulate_manage load_pe` on the Unicorn engine
  raises `codegen_extra_missing`.
- **Seed registers without a debug session.** `seed_from_target` always
  hydrates memory; the regs pull only lands when a `debug_manage` session
  is attached on the kernel view (the agent's GetRegs RPC has no thread
  selector). Without one the response carries a `regs_error` hole.
- **`Windows fatal exception: access violation` under faulthandler.**
  Unicorn's Windows port dispatches hooks via vectored exception
  handlers, so every hardware AV it handles internally is also
  announced by Python's faulthandler (pytest enables it by default).
  The process is fine — handled AVs only. To silence the noise:
  `pytest -p no:faulthandler`. Sessions are also closed deterministically
  via an `atexit` hook so native handles never outlive module teardown.
