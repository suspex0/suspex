"""Shared tool-catalog helpers: snapshot load, live rebuild, README table.

One implementation serves three consumers:

- ``scripts/gen_tool_catalog.py`` (thin CLI: regenerate the JSON snapshot
  and the README tool-table block),
- ``tests/test_tool_catalog.py`` (snapshot-vs-live drift test),
- ``tests/test_docs_drift.py`` (SKILL count + README table drift tests),
  and later Part 4's prompt test.

The catalog shape is::

    {"tools": [{"tool": "target_manage",
                "actions": ["connect", ...],
                "alias_of": null,
                "readonly": false}, ...]}

sorted by tool name, ``json.dumps(indent=2, sort_keys=True)`` + trailing
newline, so regeneration is byte-idempotent.
"""

from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ORCHESTRATOR_DIR = TESTS_DIR.parent
REPO_ROOT = ORCHESTRATOR_DIR.parent

CATALOG_PATH = TESTS_DIR / "tool_catalog.json"
PYPROJECT_PATH = ORCHESTRATOR_DIR / "pyproject.toml"
SERVER_PY_PATH = ORCHESTRATOR_DIR / "src" / "suspex" / "server.py"
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
README_PATH = REPO_ROOT / "README.md"
SKILL_PATH = REPO_ROOT / ".kilo" / "skills" / "suspex0" / "SKILL.md"

# tool name -> (module, *_ACTIONS constant) collecting each tool's verb list,
# or None for an open passthrough surface. ``findings_manage`` is the
# deprecated v0.18 alias of ``knowledge_manage`` and forwards its whole
# surface, so it maps to the same constant. ida_manage / ghidra_manage
# deliberately have NO action enum (every unknown verb is forwarded
# verbatim to the analysis backend) — null in the catalog. Add new tools
# HERE and regenerate the snapshot.
_TOOL_ACTIONS: dict[str, tuple[str, str] | None] = {
    "bin_manage": ("suspex.mcp.tools.bin", "_BIN_ACTIONS"),
    "bp_manage": ("suspex.mcp.tools.bp", "BP_ACTIONS"),
    "debug_manage": ("suspex.mcp.tools.debug", "DEBUG_ACTIONS"),
    "device_manage": ("suspex.mcp.tools.device", "DEVICE_ACTIONS"),
    "dump_manage": ("suspex.mcp.tools.dump", "DUMP_ACTIONS"),
    "emulate_manage": ("suspex.mcp.tools.emulate", "EMU_ACTIONS"),
    "event_manage": ("suspex.mcp.tools.events", "EVENT_ACTIONS"),
    "exec_manage": ("suspex.mcp.tools.exec_", "EXEC_ACTIONS"),
    "file_manage": ("suspex.mcp.tools.files", "FILE_ACTIONS"),
    "findings_manage": ("suspex.mcp.tools.knowledge", "KNOWLEDGE_ACTIONS"),
    "ghidra_manage": None,
    "ida_manage": None,
    "knowledge_manage": ("suspex.mcp.tools.knowledge", "KNOWLEDGE_ACTIONS"),
    "mem_rw": ("suspex.mcp.tools.mem", "MEM_ACTIONS"),
    "reg_manage": ("suspex.mcp.tools.reg", "REG_ACTIONS"),
    "script_manage": ("suspex.mcp.tools.scripts", "SCRIPT_ACTIONS"),
    "screen_manage": ("suspex.mcp.tools.screen", "SCREEN_ACTIONS"),
    "symbols_manage": ("suspex.mcp.tools.symbols", "SYMBOL_ACTIONS"),
    "target_manage": ("suspex.mcp.tools.target", "TARGET_ACTIONS"),
    "value_manage": ("suspex.mcp.tools.value", "VALUE_MANAGE_ACTIONS"),
    "watchdog_manage": ("suspex.mcp.tools.watchdog", "WDG_ACTIONS"),
}

# deprecated aliases: name -> canonical tool
_ALIASES: dict[str, str] = {
    "findings_manage": "knowledge_manage",
}

# README tool-table rows: name -> coverage one-liner. Order matches the
# long-standing README table (not alphabetical) to keep the diff stable;
# wording copied verbatim from the pre-CI README so regeneration starts
# as a no-op. Every non-alias tool MUST have an entry — the generator
# fails loudly on a new tool until it gets a row here.
TOOL_PURPOSE: dict[str, str] = {
    'target_manage':
        "connect / disconnect / reconnect of named target views (`kernel` driver-backed, `name='user'` driver-free umagent), status, targets, sysinfo, host_info (machine + security-posture fingerprint), driver_load / driver_unload (response carries merged driver/service state), parity (kernel-vs-usermode byte-for-byte check), wait_connectable, wait_boot_change (block until the view's boot identity flips — post-BSOD reconnect), post-crash forensics (recent_ops, recent_ops_agent, crash_state — auto-pulls + parses the newest target minidump on new_boot or `include_dump=true`). Multi-agent: whoami, list_peers, release_peer, subscribe_peers. Machine registry (v0.30): machines_register / machines_set / machines_unregister / machines — purpose/note/trust metadata + endpoints persisted in artifacts/targets.json (no restart); trust gates actuator verbs via `security.min_trust_actuator`.",
    'mem_rw':
        "read / write / alloc / free / protect across user, kernel and physical space; probe_va; inventory: modules, process_list, threads, vad, handles, imports, exports, heaps, phys_ranges, pool_scan, obj_enum, va_translate; pattern_scan + scan_start / scan_status / scan_result / scan_cancel / scan_list background jobs; watch / watch_list / watch_stop change polling; resolve (address ↔ module+offset), resolve_range / dps (every pointer qword in a range → module!sym+off), dt (`value='_KTRAP_FRAME'` named-type read), idt (per-CPU IDT dump, off-allowlist handlers flagged `suspicious`), walk_list, read_qwords, read_unicode_string, read_ansi_string, `decode=` (PDB-decoded struct reads); strings / iocs / entropy over a live range; disasm / assemble (codegen extra; honors `space='physical'`).",
    'debug_manage':
        'DbgEng user-mode debugging: launch, attach, detach, continue, step_into / step_over, regs / set_regs, threads, stacktrace, read, write, regions, events (from_seq replay), cmd (raw dbgeng).',
    'bp_manage':
        'add / remove / enable / disable / list for software (int3 via dbgeng) and hardware (DR0–3 via the driver, per-thread or `global`) breakpoints; events drains hw-BP hits (kernel int1 hook, DbgEng debug-port fallback for user-space bps).',
    'exec_manage':
        "run_exe (args_list for quoting-safe args), run_cmd, run_powershell (script_b64 for -EncodedCommand), run_script (upload local_path / inline script=, shell auto-detect); background=true detaches any run_* verb via run_detached; run_detached + detached_status / detached_tail / detached_kill for anything that can hang; timeout_s per-call orchestrator deadline; persistent shells (start_shell / write_console / read_console / stop_shell); kill_process, suspend, resume; call (v15 — synchronous in-context function call: remote thread + param-block trampoline for `space='user'`, driver work-item thunk at PASSIVE_LEVEL for `space='kernel'`; returns rax + exception/timeout detail; gated by `security.allow_function_call`, address accepts `module!export` / `module+offset`).",
    'file_manage':
        "upload / download (recursive=true mirrors a remote dir tree into artifacts/downloads/), read (inline ranged file bytes, decode=, side='orchestrator' for artifacts), dump_module (user + kernel PE dumps), hash, list_dir (remote FS), delete, yara, tail, follow_start / follow_poll / follow_stop / follow_list (streamed `tail -f`); orchestrator-side artifacts: read_artifact, grep_artifact, list_artifacts, ingest (local file → artifacts/).",
    'ida_manage':
        'Headless idalib-mcp sessions: open, open_async, open_status, list, close, schemas; shim extensions create_function, exec_idapython, idb_save, ida_status, ida_log, get_struct_member; every other action forwards verbatim as an idalib-mcp tool name.',
    'ghidra_manage':
        'Headless Ghidra engine (opt-in `ghidra.enabled`): same session surface as ida_manage (open, open_async, open_status, list, close, schemas, jobs) over ONE shared JVM + shared project hosting N programs. Decompile, disasm, P-code, xrefs, callgraph, imports/exports, strings, pattern/qword scans, rename/retype/comment/patch, struct layout (`dump_layout` feeds symbols_manage), `exec_ghidra_script` escape hatch; every other action forwards verbatim as a pyghidra backend tool name. Needs Ghidra install + JDK + pyghidra; see `ghidra:` block in configs/example.yaml.',
    'emulate_manage':
        'CPU-emulation sessions (speakeasy default, unicorn escape hatch; codegen extra): create, load_shellcode / load_pe, run, step, regs / set_regs, mem_read / mem_write / map / unmap, hook_add / hook_remove, snapshot / restore, seed_from_target, list, close.',
    'bin_manage':
        'Static binary analysis without IDA — artifact `path`/`sha256` or a live module image (`source="memory"`). Parse: info, sections, imports, exports, hashes, imphash, sec, caps. Byte surface: strings, iocs, entropy, scan. Engine: funcs, disasm_func, cfg, xrefs, paths, callgraph — images over ~512 KiB exec background the inventory build (`analyze`, `analyze_status`, `analyze_list`; re-issue once `done`, it hits the warm cache). Drivers: irp_surface, ioctl_surface. Plus audit, diff, pseudo and the ROP passes gadgets, gadget_check, chain_check.',
    'symbols_manage':
        'PDB-backed symbol/type queries: info, ensure (MSDL download/cache), resolve (name → RVA/VA), lookup (VA → nearest symbol), layout; IDA-dumped layout cache: struct_info, resolve_member, enum_info, layouts.',
    'device_manage':
        'ioctl — send one CTL_CODE to a device (double-gated actuator; a bad code can bugcheck the target); read-only etw_providers / etw_sessions inventory.',
    'event_manage':
        'Kernel notify-event stream (process/thread create+exit, image load, bp_hit): subscribe, poll, unsubscribe, list, stats.',
    'watchdog_manage':
        'Wedge→bugcheck watchdog: arm, kick, disarm, list; auto_kick / auto_status / auto_stop keep the target alive only while the orchestrator runs.',
    'script_manage':
        'Plugins under `plugins/` (local `scripts_user/` overlay shadows them): list, run, history.',
    'knowledge_manage':
        'Shared cross-agent knowledge base: record, update, list, add_evidence, sessions, about, search (FTS), annotate, link, mark_stale, artifacts, export_json. `findings_manage` remains as a deprecated alias.',
    'reg_manage':
        "Remote registry get / set / enum / delete — `wow64_32` 32-bit view, `create_subkey`, `recursive` subtree delete, `impersonate` for another user's HKCU.",
    'value_manage':
        'Pure-compute, target-less value ops: cast, views, pack / unpack, swap, split, join, bits, err_lookup, time, guid, encode / decode, str_convert, hash, eval, constants, ioctl_decode / ioctl_encode.',
    'dump_manage':
        "Kernel/usermode crash-dump triage without leaving MCP: `latest` pulls the newest `C:\\Windows\\Minidump\\*.dmp` off the target and parses it (bugcheck code+name, the 4 params, context, stack qwords — resolved to module!sym+off when the dump is same-boot-fresh); `parse` takes a local `path`, an artifact-store `sha256`, or a `remote_path` pulled first. Suspex-watchdog bugchecks self-identify (`fired_by='suspex_watchdog'`).",
    'screen_manage':
        "Visual inspection of the interactive session (v15 — runs in a session-1 worker re-launch; a Session-0 service can't see the user desktop): `capture` screenshots the desktop (DXGI duplication) or one window (WGC by hwnd/pid/title/process_name) to artifacts/screenshots/ (dims, sha256, opt-in `embed` base64); `windows` lists windows grouped by process in Z order with full metadata (class, style/exstyle, status, window/client rects, placement, z-order, owner/parent, pid/tid, process path, hinstance, visible/enabled/min/max/topmost/layered/toolwindow/cloaked, dpi) — `include_hidden=True` opts into hidden/invisible/cloaked windows, `include_details=False` for the compact legacy list; `displays` shows monitor topology.",
}

README_TABLE_START = "<!-- tool-table:start -->"
README_TABLE_END = "<!-- tool-table:end -->"


def load_catalog() -> dict:
    """Load the committed snapshot ``tests/tool_catalog.json``."""
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _minimal_context():
    """A throwaway Context good enough to ``build_server`` on.

    Mirrors the fixture pattern in ``tests/_multi_fakes.py`` but with a
    process-lifetime temp dir (findings DB + artifacts) and no fake
    agents — tool registration never connects anywhere.
    """
    from suspex.config import SuspexConfig
    from suspex.findings import FindingsLedger
    from suspex.ida_bridge import IdaBridge, IdaConfigLite
    from suspex.mcp.tools import Context
    from suspex.session import Session

    global _TEMP_ROOT
    if _TEMP_ROOT is None:
        _TEMP_ROOT = Path(tempfile.mkdtemp(prefix="suspex-tool-catalog-"))
    artifacts = _TEMP_ROOT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    cfg = SuspexConfig()
    cfg.artifacts.dir = str(artifacts)
    ledger = FindingsLedger(artifacts / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), artifacts)
    return Context(cfg=cfg, session=Session(cfg), ledger=ledger, bridge=bridge)


_TEMP_ROOT: Path | None = None


def _actions_for(name: str) -> list[str] | None:
    """Action list from the tool module's ``*_ACTIONS`` constant.

    Open-passthrough tools (ida_manage, ghidra_manage) have no enum —
    they return ``None``. Unknown tool names raise so a freshly
    registered tool forces a map + snapshot update instead of silently
    drifting.
    """
    if name not in _TOOL_ACTIONS:
        raise ValueError(
            f"tool {name!r} is not in _TOOL_ACTIONS (tests/_catalog.py) — "
            "add its actions constant (or None for an open passthrough "
            "surface) and regenerate the catalog")
    ref = _TOOL_ACTIONS[name]
    if ref is None:
        return None
    module = importlib.import_module(ref[0])
    return sorted(getattr(module, ref[1]))


def by_registration_names() -> set[str]:
    """The registered tool names recorded in the map (test helper)."""
    return set(_TOOL_ACTIONS)


async def build_live_catalog() -> dict:
    """Enumerate the live FastMCP registry into the catalog shape."""
    from suspex.mcp.tools import build_server

    server = build_server(_minimal_context())
    tools = await server.list_tools()
    entries: list[dict] = []
    for tool in sorted(tools, key=lambda t: t.name):
        ann = getattr(tool, "annotations", None)
        if ann is None:
            readonly = False
        elif hasattr(ann, "read_only_hint"):
            readonly = bool(ann.read_only_hint)
        else:
            readonly = bool(getattr(ann, "readOnlyHint", False))
        entries.append({
            "tool": tool.name,
            "actions": _actions_for(tool.name),
            "alias_of": _ALIASES.get(tool.name),
            "readonly": readonly,
        })
    return {"tools": entries}


def catalog_to_json(catalog: dict) -> str:
    """Stable serialization: sorted keys, indent 2, trailing newline."""
    return json.dumps(catalog, indent=2, sort_keys=True) + "\n"


def readme_table_block(catalog: dict) -> str:
    """The README tool-surface table, regenerated from the catalog.

    One row per real (non-alias) tool: ``| ``tool`` | purpose |``. Row
    order follows TOOL_PURPOSE (the README's long-standing order), and a
    real tool without a TOOL_PURPOSE entry is a hard error — the docs
    must describe the whole surface.
    """
    real = [e for e in catalog["tools"] if not e["alias_of"]]
    missing = sorted(e["tool"] for e in real if e["tool"] not in TOOL_PURPOSE)
    if missing:
        raise ValueError(
            "no TOOL_PURPOSE one-liner for: " + ", ".join(missing) +
            " (tests/_catalog.py) — add one and regenerate")
    lines = ["| Tool | Coverage |", "|---|---|"]
    for entry in real:
        lines.append(f"| `{entry['tool']}` | {TOOL_PURPOSE[entry['tool']]} |")
    return "\n".join(lines)


def readme_full_block(catalog: dict) -> str:
    """Markers + table, i.e. the exact README region owned by the catalog."""
    return (README_TABLE_START + "\n" + readme_table_block(catalog) +
            "\n" + README_TABLE_END)
