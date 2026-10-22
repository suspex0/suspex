"""v0.17 A-2: text-line collapse for list actions on
``verbosity="compact"``.

Extends the finalize post-processor with a per-``(tool, action)``
transform table (:data:`suspex.mcp._envelope.COMPACT_TRANSFORMS`).
When ``verbosity="compact"`` matches a registered entry the row list
is rewritten into a list of strings — a lot easier for a terminal
reader to scan and ~55-70% cheaper on wire tokens for a 64-row disasm.

Coverage:

  * ``disasm``  — ``{addr, bytes, mnemonic, op_str}`` collapses.
  * ``handles`` — ``{handle, type_name, object, name}`` collapses.
  * ``vad``     — ``{start, end, protect, vad_type, commit_charge}`` collapses.
  * ``heaps``   — ``{handle, base, committed, ...}`` collapses (source key
                   ``"heaps"``, not ``"items"``).
  * ``exports`` — ``{name, ordinal, rva, address, forwarder}`` collapses
                   (source key ``"items"`` since the exports action
                   migrated to ``list_envelope``).
  * ``imports`` — hooked-entry annotation preserved.
  * v0.31: the collapse fires at the default ``verbosity="normal"`` as well
    as ``"compact"``; ``"full"``/``"raw"`` preserve the dict shape.
  * Non-registered ``(tool, action)`` pairs are untouched.
"""

from __future__ import annotations

from suspex.mcp._envelope import (
    COMPACT_TRANSFORMS,
    EnvelopeOpts,
    envelope_ok,
    finalize,
)


def _mk(tool: str, action: str, data: dict) -> dict:
    """Build a raw envelope with a specific ``(tool, action)``. Only the
    finalize compact-transform path cares about these two fields."""
    return envelope_ok(data, kind=action, tool=tool, action=action)


def _finalize_compact(env: dict) -> dict:
    finalize(env, opts=EnvelopeOpts(verbosity="compact"))
    return env


def _finalize_normal(env: dict) -> dict:
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    return env


# ---------------------------------------------------------------------------
# disasm
# ---------------------------------------------------------------------------

_DISASM_ROWS = [
    {"addr": 0x1000, "bytes": "90", "mnemonic": "nop", "op_str": "",
     "size": 1},
    {"addr": 0x1001, "bytes": "48 89 c8", "mnemonic": "mov",
     "op_str": "rax, rcx", "size": 3},
    {"addr": 0x1004, "bytes": "c3", "mnemonic": "ret", "op_str": "",
     "size": 1},
]


def test_compact_disasm_returns_strings():
    env = _mk("mem_rw", "disasm", {"items": [dict(r) for r in _DISASM_ROWS]})
    _finalize_compact(env)
    items = env["data"]["items"]
    assert len(items) == 3
    assert all(isinstance(line, str) for line in items)
    assert "nop" in items[0]
    assert "mov" in items[1] and "rax, rcx" in items[1]
    assert items[2].strip().endswith("ret")


def test_compact_disasm_uses_hex_address():
    env = _mk("mem_rw", "disasm", {"items": [dict(_DISASM_ROWS[0])]})
    _finalize_compact(env)
    (line,) = env["data"]["items"]
    assert "0x1000" in line


def test_compact_disasm_preserves_sym_annotation():
    env = _mk("mem_rw", "disasm", {"items": [
        {"addr": 0x2000, "bytes": "e8 12 34", "mnemonic": "call",
         "op_str": "0x12345", "size": 5, "sym": "ntoskrnl!ExAllocatePool"},
    ]})
    _finalize_compact(env)
    (line,) = env["data"]["items"]
    assert "ntoskrnl!ExAllocatePool" in line


def test_compact_disasm_accepts_hex_string_address():
    """After ``_hexify_dict`` the address may already be a ``"0x…"``
    string — the compact renderer MUST handle both."""
    env = _mk("mem_rw", "disasm", {"items": [
        {"address": "0x1000", "bytes": "90", "mnemonic": "nop",
         "op_str": "", "size": 1},
    ]})
    _finalize_compact(env)
    (line,) = env["data"]["items"]
    assert "0x1000" in line and "nop" in line


def test_compact_disasm_on_at_normal():
    # v0.31: row-collapse now fires at the default "normal" too, not only
    # "compact" — the savings apply by default.
    env = _mk("mem_rw", "disasm", {"items": [dict(_DISASM_ROWS[0])]})
    _finalize_normal(env)
    (row,) = env["data"]["items"]
    assert isinstance(row, str)
    assert "nop" in row


# ---------------------------------------------------------------------------
# handles
# ---------------------------------------------------------------------------

def test_compact_handles():
    env = _mk("mem_rw", "handles", {"items": [
        {"handle": 0x8c, "type_name": "File",
         "object": 0xFFFFAAAA00000000, "granted_access": 0x100001,
         "name": r"\Device\HarddiskVolume1\Windows\System32\ntdll.dll"},
        {"handle": 0x14, "type_name": "Key",
         "object": 0xFFFFBBBB00000000, "granted_access": 0,
         "name": ""},
    ]})
    _finalize_compact(env)
    items = env["data"]["items"]
    assert isinstance(items[0], str)
    assert "handle=0x8c" in items[0]
    assert "type=File" in items[0]
    assert r"path=\Device\HarddiskVolume1\Windows\System32\ntdll.dll" in items[0]
    # Unnamed handle drops the path segment entirely.
    assert "path=" not in items[1]


def test_compact_handles_on_at_normal():
    # v0.31: collapse at the default "normal"; full/raw keep dict rows.
    env = _mk("mem_rw", "handles", {"items": [
        {"handle": 1, "type_name": "File", "object": 0,
         "granted_access": 0, "name": ""},
    ]})
    _finalize_normal(env)
    (row,) = env["data"]["items"]
    assert isinstance(row, str)
    assert "type=File" in row


# ---------------------------------------------------------------------------
# vad
# ---------------------------------------------------------------------------

def test_compact_vad():
    env = _mk("mem_rw", "vad", {"items": [
        {"start": 0x10000, "end": 0x20000, "protect": 0x40,
         "vad_type": 2, "commit_charge": 4096},
    ]})
    _finalize_compact(env)
    (line,) = env["data"]["items"]
    assert isinstance(line, str)
    assert "0x10000-0x20000" in line
    assert "protect=0x40" in line
    assert "type=2" in line
    assert "commit=4096" in line


# ---------------------------------------------------------------------------
# heaps — source key is "heaps", not "items"
# ---------------------------------------------------------------------------

def test_compact_heaps_uses_heaps_source_key():
    env = _mk("mem_rw", "heaps", {"count": 1, "heaps": [
        {"handle": 0x1000000, "flags": 0, "base": 0x1000000,
         "committed": 0x8000, "reserved": 0x100000, "blocks": []},
    ]})
    _finalize_compact(env)
    heaps = env["data"]["heaps"]
    assert isinstance(heaps[0], str)
    assert "heap=0x1000000" in heaps[0]
    assert "committed=32768" in heaps[0]
    assert "blocks=0" in heaps[0]


def test_compact_heaps_reports_block_count():
    env = _mk("mem_rw", "heaps", {"count": 1, "heaps": [
        {"handle": 0x1000000, "flags": 0, "base": 0x1000000,
         "committed": 0, "reserved": 0,
         "blocks": [{"address": i, "size": 8, "flags": 0}
                     for i in range(5)]},
    ]})
    _finalize_compact(env)
    (line,) = env["data"]["heaps"]
    assert "blocks=5" in line


# ---------------------------------------------------------------------------
# exports / imports — source key is "entries"
# ---------------------------------------------------------------------------

def test_compact_exports_uses_items_source_key():
    env = _mk("mem_rw", "exports", {"count": 2, "items": [
        {"name": "NtAllocateVirtualMemory", "ordinal": 24,
         "rva": 0x1234, "address": 0x77770000 + 0x1234, "forwarder": ""},
        {"name": "AmsiScanBuffer", "ordinal": 0, "rva": 0x2000,
         "address": 0, "forwarder": "amsi.dll!AmsiScanBuffer"},
    ]})
    _finalize_compact(env)
    entries = env["data"]["items"]
    assert isinstance(entries[0], str)
    assert "NtAllocateVirtualMemory" in entries[0]
    assert "ord=24" in entries[0]
    # Forwarder rendered with an arrow.
    assert "→" in entries[1]
    assert "amsi.dll!AmsiScanBuffer" in entries[1]


def test_compact_imports_marks_hooked_entries():
    env = _mk("mem_rw", "imports", {"count": 2, "hooked": 1, "items": [
        {"dll": "ntdll.dll", "name": "NtReadFile", "ordinal": 0,
         "iat_slot": 0x140001000, "resolved": 0x77770000,
         "resolved_module": "ntdll.dll", "hooked": False},
        {"dll": "kernel32.dll", "name": "CreateFileW", "ordinal": 0,
         "iat_slot": 0x140001010, "resolved": 0xDEADBEEF,
         "resolved_module": "detours.dll", "hooked": True},
    ]})
    _finalize_compact(env)
    entries = env["data"]["items"]
    assert isinstance(entries[0], str)
    assert "ntdll.dll!NtReadFile" in entries[0]
    assert "[HOOKED]" not in entries[0]
    assert "kernel32.dll!CreateFileW" in entries[1]
    assert "[HOOKED]" in entries[1]
    assert "detours.dll" in entries[1]


def test_compact_imports_falls_back_to_ordinal_when_name_empty():
    env = _mk("mem_rw", "imports", {"count": 1, "items": [
        {"dll": "advapi32.dll", "name": "", "ordinal": 42,
         "iat_slot": 0x140001020, "resolved": 0,
         "resolved_module": "", "hooked": False},
    ]})
    _finalize_compact(env)
    (line,) = env["data"]["items"]
    assert "advapi32.dll!#42" in line


# ---------------------------------------------------------------------------
# v0.31 generic kv-collapse (_text_line_kv) for the extra list actions
# ---------------------------------------------------------------------------

def test_compact_kv_process_list_at_normal():
    env = _mk("mem_rw", "process_list", {"items": [
        {"pid": 4, "parent_pid": 0, "image_name": "System",
         "start_va": 0x1400, "wow64": False},
        {"pid": 1234, "parent_pid": 4, "image_name": "notepad.exe",
         "start_va": 0x7ff600000000, "wow64": True},
    ]})
    _finalize_normal(env)
    items = env["data"]["items"]
    assert all(isinstance(line, str) for line in items)
    assert "pid=4" in items[0] and "image_name=System" in items[0]
    assert "start_va=0x1400" in items[0]        # address key -> hex
    assert "wow64" not in items[0]              # false bool dropped
    assert "wow64" in items[1]                  # true bool -> bare flag


def test_compact_kv_reg_enum_uses_values_source_key():
    env = _mk("reg_manage", "enum", {
        "subkeys": ["ControlSet001", "ControlSet002"],
        "values": [{"name": "Start", "type": 4, "size": 4}],
    })
    _finalize_normal(env)
    # subkeys (already compact strings) untouched; values collapsed.
    assert env["data"]["subkeys"] == ["ControlSet001", "ControlSet002"]
    (val_line,) = env["data"]["values"]
    assert isinstance(val_line, str)
    assert "name=Start" in val_line and "type=4" in val_line


def test_compact_kv_skips_nested_values():
    env = _mk("mem_rw", "threads", {"items": [
        {"tid": 8, "pid": 4, "teb": 0xabc0, "context_regs": {"rip": 1}},
    ]})
    _finalize_normal(env)
    (line,) = env["data"]["items"]
    assert "tid=8" in line and "teb=0xabc0" in line
    assert "context_regs" not in line  # nested dict dropped


# ---------------------------------------------------------------------------
# non-registered actions & verbosity gates
# ---------------------------------------------------------------------------

def test_compact_untouched_for_unregistered_action():
    """A ``(tool, action)`` pair not in ``COMPACT_TRANSFORMS`` is untouched
    at ``verbosity="compact"`` — the caller still gets structured rows."""
    env = _mk("mem_rw", "modules", {"items": [
        {"base": 0x1000, "size": 0x100, "name": "nt"},
    ]})
    _finalize_compact(env)
    (row,) = env["data"]["items"]
    assert isinstance(row, dict)
    assert row["name"] == "nt"


def test_compact_untouched_for_full_verbosity():
    env = _mk("mem_rw", "disasm", {"items": [dict(_DISASM_ROWS[0])]})
    finalize(env, opts=EnvelopeOpts(verbosity="full"))
    (row,) = env["data"]["items"]
    assert isinstance(row, dict)
    assert row["mnemonic"] == "nop"


def test_compact_untouched_for_raw_verbosity():
    env = _mk("mem_rw", "disasm", {"items": [dict(_DISASM_ROWS[0])]})
    finalize(env, opts=EnvelopeOpts(verbosity="raw"))
    (row,) = env["data"]["items"]
    assert isinstance(row, dict)


def test_compact_transforms_registry_completeness():
    """Regression: every entry advertised in the plan (A-2) is in the map,
    and every registered ``callable`` has a compatible signature.

    If a future rework removes an entry, this asserts loudly at CI time
    so an unrelated worker doesn't accidentally regress the compact
    contract.
    """
    expected = {
        ("mem_rw", "disasm"),
        ("mem_rw", "handles"),
        ("mem_rw", "vad"),
        ("mem_rw", "heaps"),
        ("mem_rw", "exports"),
        ("mem_rw", "imports"),
        # v0.31 generic kv-collapse additions
        ("mem_rw", "process_list"),
        ("mem_rw", "threads"),
        ("debug_manage", "threads"),
        ("debug_manage", "stacktrace"),
        ("debug_manage", "regions"),
        ("knowledge_manage", "list"),
        ("knowledge_manage", "search"),
        ("reg_manage", "enum"),
    }
    assert set(COMPACT_TRANSFORMS) >= expected
    for key, (source_key, fn) in COMPACT_TRANSFORMS.items():
        assert isinstance(source_key, str)
        assert callable(fn)
        # Empty-list roundtrip must not crash.
        assert fn([]) == []
