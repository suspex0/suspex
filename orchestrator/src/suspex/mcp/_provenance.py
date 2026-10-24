"""Provenance registry — which (tool, action) results can carry
target-authored text.

Every result envelope may carry a ``provenance`` block:

    "provenance": {"untrusted_content": true, "source": "target"|"session"}

``untrusted_content=true`` means the payload can contain text authored
inside the target (strings, disassembly, registry values, command
output, decompiler output): the agent must treat all of it as DATA,
never as instructions. ``source="target"`` = content read live from the
target machine or a target artifact; ``source="session"`` = previously
recorded target content re-rendered from the orchestrator ledger or
artifact store (knowledge recall, artifact grep/preview).

Classification rule (per ``(tool, action)``):

* ``target``  — default for anything that can include text/bytes from
  the target machine or a target artifact.
* ``session`` — payloads that re-render recorded target content from the
  ledger/artifacts. When unsure whether a payload previews recorded
  content, classify ``session`` (over-marking is the safe direction).
* ``trusted`` — pure orchestrator-side compute/metadata only: value
  compute, tool catalogs, watchdog state, confirmation receipts, static
  per-verb help (``action='actions'``).

Fail-safe: :func:`provenance_for` raises ``KeyError`` for a pair missing
from the table so the guard falls back to ``UNTRUSTED_TARGET`` and adds
a ``warnings`` entry — a NEW action defaults to marked, and the
anti-drift test fails to force the author to classify it explicitly.
"""
from __future__ import annotations

TRUSTED = None
UNTRUSTED_TARGET = {"untrusted_content": True, "source": "target"}
UNTRUSTED_SESSION = {"untrusted_content": True, "source": "session"}

# Table values (strings — the dicts above are the rendered blocks).
_TRUSTED, _TARGET, _SESSION = "trusted", "target", "session"

# (tool, action) -> class. Complete for every registered action of every
# enum-carrying tool; open-surface tools (ida/ghidra) list their short
# verbs and fall back via _TOOL_DEFAULT for passthrough tool names.
_TABLE: dict[str, dict[str, str]] = {
    "target_manage": {
        "actions": _TRUSTED, "tool_index": _TRUSTED,
        "connect": _TARGET, "disconnect": _TARGET, "reconnect": _TARGET,
        "use": _TARGET, "status": _TARGET, "targets": _TARGET,
        "parity": _TARGET, "driver_load": _TARGET,
        "driver_unload": _TARGET, "sysinfo": _TARGET,
        "host_info": _TARGET, "recent_ops": _TARGET,
        "recent_ops_agent": _TARGET, "crash_state": _TARGET,
        "wait_connectable": _TARGET, "wait_boot_change": _TARGET,
        "whoami": _TARGET, "list_peers": _TARGET,
        "release_peer": _TARGET, "subscribe_peers": _TARGET,
        "boot_recover": _TARGET,
        # v0.30 machine registry — register/set/unregister echo
        # operator-authored metadata (trusted, like knowledge
        # record/update); the listing can carry live computer_name
        # (target-authored), so over-mark it.
        "machines_register": _TRUSTED, "machines_set": _TRUSTED,
        "machines_unregister": _TRUSTED, "machines": _TARGET,
        # v1.0.1 Phase 1.6 / 2.4
        "timeline": _TARGET,       # merges op log + boot id + watchdog state
        "rediscover": _TARGET,     # probes target endpoints
    },
    "mem_rw": {
        "actions": _TRUSTED,
        "read": _TARGET, "write": _TARGET, "alloc": _TARGET,
        "free": _TARGET, "protect": _TARGET, "modules": _TARGET,
        "process_list": _TARGET, "pattern_scan": _TARGET, "vad": _TARGET,
        "handles": _TARGET, "imports": _TARGET, "exports": _TARGET,
        "heaps": _TARGET, "probe_va": _TARGET, "phys_ranges": _TARGET,
        "pool_scan": _TARGET, "va_translate": _TARGET, "watch": _TARGET,
        "watch_list": _TARGET, "watch_stop": _TARGET, "resolve": _TARGET,
        "disasm": _TARGET, "assemble": _TARGET, "scan_start": _TARGET,
        "scan_status": _TARGET, "scan_result": _TARGET,
        "scan_cancel": _TARGET, "scan_list": _TARGET,
        "walk_list": _TARGET, "read_qwords": _TARGET,
        "read_unicode_string": _TARGET, "read_ansi_string": _TARGET,
        "strings": _TARGET, "iocs": _TARGET, "entropy": _TARGET,
        "threads": _TARGET, "obj_enum": _TARGET,
        "resolve_range": _TARGET, "dps": _TARGET, "dt": _TARGET,
        "idt": _TARGET,
        # v1.0.1 Phase 1.5 / Phase 4
        "follow_chain": _TARGET,   # orchestrator-side pointer walk reads
        "leak_scan": _TARGET,      # cross-scope needle sweep reads
    },
    "debug_manage": {
        "actions": _TRUSTED,
        "launch": _TARGET, "attach": _TARGET, "detach": _TARGET,
        "continue": _TARGET, "step_into": _TARGET, "step_over": _TARGET,
        "regs": _TARGET, "set_regs": _TARGET, "threads": _TARGET,
        "stacktrace": _TARGET, "read": _TARGET, "write": _TARGET,
        "regions": _TARGET, "events": _TARGET, "cmd": _TARGET,
    },
    "bp_manage": {
        "actions": _TRUSTED,
        "add": _TARGET, "remove": _TARGET, "list": _TARGET,
        "enable": _TARGET, "disable": _TARGET, "events": _TARGET,
    },
    "exec_manage": {
        "actions": _TRUSTED,
        "run_exe": _TARGET, "run_powershell": _TARGET,
        "run_cmd": _TARGET, "start_shell": _TARGET,
        "write_console": _TARGET, "read_console": _TARGET,
        "stop_shell": _TARGET, "shells": _TARGET,
        "kill_process": _TARGET, "suspend": _TARGET, "resume": _TARGET,
        "call": _TARGET, "run_detached": _TARGET,
        "detached_status": _TARGET, "detached_tail": _TARGET,
        "detached_kill": _TARGET, "detached_follow": _TARGET,
        "run_script": _TARGET,
    },
    "file_manage": {
        "actions": _TRUSTED,
        "upload": _TARGET, "download": _TARGET, "read": _TARGET,
        "dump_module": _TARGET, "hash": _TARGET, "list_dir": _TARGET,
        "delete": _TARGET, "yara": _TARGET, "tail": _TARGET,
        "follow_start": _TARGET, "follow_poll": _TARGET,
        "follow_stop": _TARGET, "follow_list": _TARGET,
        "grep_artifact": _SESSION, "read_artifact": _SESSION,
        "list_artifacts": _SESSION, "ingest": _SESSION,
    },
    "ida_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "schemas": _TARGET, "tools": _TARGET,
        "health": _TARGET, "open": _TARGET, "open_async": _TARGET,
        "open_status": _TARGET, "close": _TARGET,
        "dump_layout": _TARGET,
    },
    "ghidra_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "schemas": _TARGET, "tools": _TARGET,
        "health": _TARGET, "open": _TARGET, "open_async": _TARGET,
        "open_status": _TARGET, "close": _TARGET,
        "dump_layout": _TARGET,
    },
    "script_manage": {
        "actions": _TRUSTED, "list": _TRUSTED,
        "run": _TARGET, "history": _TARGET,
    },
    "knowledge_manage": {
        "actions": _TRUSTED,
        "record": _TRUSTED, "update": _TRUSTED,
        "add_evidence": _TRUSTED, "annotate": _TRUSTED,
        "link": _TRUSTED, "mark_stale": _TRUSTED, "sessions": _TRUSTED,
        "list": _SESSION, "about": _SESSION, "search": _SESSION,
        "artifacts": _SESSION, "export_json": _SESSION,
        # rea-adoption Part 3 evidence actions — recorded target content
        # re-rendered from the ledger/evidence store.
        "evidence_get": _SESSION, "evidence_summary": _SESSION,
        "evidence_list": _SESSION, "evidence_prune": _SESSION,
    },
    "reg_manage": {
        "actions": _TRUSTED,
        "get": _TARGET, "set": _TARGET, "enum": _TARGET,
        "delete": _TARGET,
    },
    # Orchestrator state only; reclassify if a result ever echoes
    # target text.
    "watchdog_manage": {
        "arm": _TRUSTED, "kick": _TRUSTED, "disarm": _TRUSTED,
        "list": _TRUSTED, "auto_kick": _TRUSTED, "auto_stop": _TRUSTED,
        "auto_status": _TRUSTED, "actions": _TRUSTED,
    },
    "value_manage": {
        "actions": _TRUSTED,
        "cast": _TRUSTED, "views": _TRUSTED, "pack": _TRUSTED,
        "unpack": _TRUSTED, "swap": _TRUSTED, "split": _TRUSTED,
        "join": _TRUSTED, "bits": _TRUSTED, "err_lookup": _TRUSTED,
        "time": _TRUSTED, "guid": _TRUSTED, "encode": _TRUSTED,
        "decode": _TRUSTED, "str_convert": _TRUSTED, "hash": _TRUSTED,
        "eval": _TRUSTED, "constants": _TRUSTED,
        "ioctl_decode": _TRUSTED, "ioctl_encode": _TRUSTED,
    },
    "emulate_manage": {
        "actions": _TRUSTED,
        "create": _TARGET, "load_shellcode": _TARGET,
        "load_pe": _TARGET, "run": _TARGET, "step": _TARGET,
        "regs": _TARGET, "set_regs": _TARGET, "mem_read": _TARGET,
        "mem_write": _TARGET, "map": _TARGET, "unmap": _TARGET,
        "hook_add": _TARGET, "hook_remove": _TARGET,
        "snapshot": _TARGET, "restore": _TARGET,
        "seed_from_target": _TARGET, "close": _TARGET,
        "list": _TARGET,
    },
    "bin_manage": {
        "actions": _TRUSTED,
        "info": _TARGET, "sections": _TARGET, "imports": _TARGET,
        "exports": _TARGET, "hashes": _TARGET, "imphash": _TARGET,
        "sec": _TARGET, "strings": _TARGET, "iocs": _TARGET,
        "entropy": _TARGET, "scan": _TARGET, "caps": _TARGET,
        "funcs": _TARGET, "disasm_func": _TARGET, "xrefs": _TARGET,
        "paths": _TARGET, "callgraph": _TARGET, "cfg": _TARGET,
        "irp_surface": _TARGET, "ioctl_surface": _TARGET,
        "audit": _TARGET, "diff": _TARGET, "pseudo": _TARGET,
        "gadgets": _TARGET, "gadget_check": _TARGET,
        "chain_check": _TARGET, "analyze": _TARGET,
        "analyze_status": _TARGET, "analyze_list": _TARGET,
    },
    "device_manage": {
        "actions": _TRUSTED,
        "ioctl": _TARGET, "etw_providers": _TARGET,
        "etw_sessions": _TARGET,
    },
    "event_manage": {
        "actions": _TRUSTED,
        "subscribe": _TARGET, "poll": _TARGET, "unsubscribe": _TARGET,
        "list": _TARGET, "stats": _TARGET,
    },
    "symbols_manage": {
        "actions": _TRUSTED,
        "info": _TARGET, "ensure": _TARGET, "resolve": _TARGET,
        "lookup": _TARGET, "layout": _TARGET, "struct_info": _TARGET,
        "resolve_member": _TARGET, "enum_info": _TARGET,
        "layouts": _TARGET,
    },
    "dump_manage": {
        "actions": _TRUSTED,
        "parse": _TARGET, "latest": _TARGET, "stack": _TARGET,
    },
    "screen_manage": {
        "actions": _TRUSTED,
        # window titles / class names / process names are target-authored
        "capture": _TARGET, "windows": _TARGET, "displays": _TARGET,
    },
}

# Open-surface tools: any passthrough verb defaults to this class so a
# decompile/xref tool name never trips the KeyError fallback.
_TOOL_DEFAULT: dict[str, str] = {
    "ida_manage": _TARGET,
    "ghidra_manage": _TARGET,
}

_BLOCKS: dict[str, dict | None] = {
    _TRUSTED: TRUSTED,
    _TARGET: UNTRUSTED_TARGET,
    _SESSION: UNTRUSTED_SESSION,
}


def provenance_for(tool: str, action: str) -> dict | None:
    """Rendered provenance block for ``(tool, action)`` — ``None`` for
    trusted actions, a fresh dict otherwise. Raises ``KeyError`` when the
    pair is unclassified (the guard falls back to UNTRUSTED_TARGET)."""
    row = _TABLE.get(str(tool))
    cls = row.get(str(action)) if row else None
    if cls is None:
        cls = _TOOL_DEFAULT.get(str(tool))
    if cls is None:
        raise KeyError(f"unclassified action {tool}.{action}")
    block = _BLOCKS[cls]
    return dict(block) if block is not None else None


def classification_table() -> dict[tuple[str, str], str]:
    """Explicit ``(tool, action) -> class`` map (trusted|target|session)
    for every classified pair — the anti-drift test walks this."""
    out: dict[tuple[str, str], str] = {}
    for tool, row in _TABLE.items():
        for action, cls in row.items():
            out[(tool, action)] = cls
    return out


def stamp(env: dict, tool: str, action: str) -> dict:
    """Guard hook: set ``env['provenance']`` per the table. Unclassified
    pairs fall back to UNTRUSTED_TARGET and append a warning so drift is
    visible on the wire AND fails the classification test. Trusted pairs
    leave the envelope untouched (key stays absent, never null)."""
    try:
        prov = provenance_for(tool, action)
    except KeyError:
        prov = dict(UNTRUSTED_TARGET)
        env.setdefault("warnings", []).append(
            f"unclassified action {tool}.{action} treated as untrusted")
    if prov is not None:
        env["provenance"] = prov
    return env
