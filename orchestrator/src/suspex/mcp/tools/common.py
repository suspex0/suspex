"""Shared helpers for the split suspex0 MCP tools package.

Every ``@mcp.tool`` closure inside the per-domain modules
(``target``, ``mem``, ``debug`` ...) reads its helpers from here. The
public envelope-shaped helpers (``_j``, ``_addr``, the ``_apply_*``
filters, ``_guard`` / ``_guard_pure``, ...) keep their leading
underscore for API stability: several tests import them by name from
``suspex.mcp.tools`` and the facade in ``__init__.py`` re-exports them
unchanged.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import struct
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ...agent_client import AgentClient
from ...allowlist import TargetNotAllowed as TargetNotAllowedError
from ...caller import current_client_id
from ...config import PRIMARY_TARGET
from ...findings import FindingsLedger
from ...ida_bridge import IdaBridge, IdaBridgeError
from ...ghidra_bridge import GhidraBridge, GhidraBridgeError
from ...leases import BusyInfo, LeaseHandle, LeaseManager
from ...ownership import OwnershipRegistry
from ...parity import format_report, run_parity, verdict
from ...plugins import PluginError, discover, file_result, meta_dict, run_plugin
from ...session import AmbiguousTargetError, Session

from .context import Context

log = logging.getLogger(__name__)

try:
    from mcp.types import ToolAnnotations

    READONLY_FALSE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
    READONLY_TRUE = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
except Exception:  # pragma: no cover - annotations are cosmetic
    READONLY_FALSE = None
    READONLY_TRUE = None



def _j(data: Any) -> Any:
    # A-1 (v0.17): finalized envelopes go out as a FastMCP ``ToolResult``
    # with ``content=[]`` and ``structured_content=data`` so the same
    # payload no longer ships on the wire twice (once as
    # ``content[0].text`` and again as ``structuredContent.result``).
    #
    # Discriminator: ``_envelope.finalize`` always stamps
    # ``summary.size_bytes`` on a finalized envelope — no inner
    # ``run()`` site sets that key, and no legacy pre-envelope shape
    # produces it. That keeps every other ``_j(...)`` call site
    # (ledger evidence writes at ~1414/3676 with parity reports and
    # yara-match lists; and inner ``run()`` bodies that build a raw
    # envelope-shaped dict and rely on ``_coerce_to_envelope`` to
    # re-wrap it) on the historical ``json.dumps`` path.
    #
    # ``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` restores the pre-A-1
    # dual-emit shape for one release; see ``_envelope.to_tool_result``.
    if (
        isinstance(data, dict)
        and "ok" in data
        and isinstance(data.get("summary"), dict)
        and "size_bytes" in data["summary"]
    ):
        from .._envelope import to_tool_result as _to_tool_result
        return _to_tool_result(data)
    return json.dumps(data, indent=2, default=str)


def _one_line_desc(s: str, cap: int = 120) -> str:
    """First sentence of a tool description, hard-capped at ``cap`` chars.

    Used by ``ida_manage(action='tools')`` to strip the multi-paragraph
    docstrings the vanilla ida-pro-mcp tools carry so the discovery
    call stays inexpensive.
    """
    if not s:
        return ""
    # First line; then first sentence (either "X. Y" or trailing period).
    line = s.strip().split("\n", 1)[0].split(". ", 1)[0].rstrip()
    if line.endswith(".") and len(line) > 1:
        line = line[:-1]
    if len(line) > cap:
        return line[: max(cap - 3, 1)] + "..."
    return line


def _parse_ida_schemas_filter(args_json: str) -> set[str]:
    """Return the ``tools`` filter set parsed from ``args_json``.

    Accepts ``{"tools": ["decompile_function", ...]}`` OR
    ``{"tools": "decompile_function"}`` (bare string). Malformed
    JSON or a missing key yields an empty set so the caller keeps
    the pre-C2-1a full-dump behaviour.
    """
    if not args_json:
        return set()
    try:
        parsed = json.loads(args_json)
    except (TypeError, ValueError):
        return set()
    if not isinstance(parsed, dict):
        return set()
    raw = parsed.get("tools")
    if isinstance(raw, list):
        return {str(t) for t in raw if t}
    if isinstance(raw, str) and raw:
        return {raw}
    return set()


def _filter_ida_schemas(schemas: list[dict], wanted: set[str]) -> list[dict]:
    """Project the schema rows down to ``{name, description, inputSchema}``,
    filtered by ``wanted`` when non-empty."""
    return [{"name": t.get("name"),
             "description": t.get("description", ""),
             "inputSchema": t.get("inputSchema", {})}
            for t in schemas
            if not wanted or t.get("name") in wanted]


# Common Win32 error codes surfaced by the driver / agent as raw
# "DeviceIoControl gle=87" strings. Enriching in one place keeps the
# messages readable without touching every call site. Table lives in
# error_maps.py so `type_convert err_lookup` shares the same source of
# truth (extended there with the top ~120 NTSTATUS + HRESULT decomposers).
from ..error_maps import WIN32_ERRORS as _WIN32_ERRORS
# v0.13 dev-feedback: three response utilities.
#   _hex_addresses    render every address/size as '0x...' with `_int` mirror
#   _decode_enums     attach `<field>_decoded` (PAGE_EXECUTE_READ, ...) siblings
#   _error_enrich     classify raw error strings into {kind, hint} pairs
from .._hex_addresses import hexify_dict as _hexify_dict, hexify as _hexify
from .._decode_enums import attach_decoded_list as _decode_list, attach_decoded as _decode
from .._error_enrich import (
    enrich_error as _enrich_error,
    enrich_win32 as _enrich_win32_v2,
    classify as _classify,
)
# v0.14 unified envelope — every response funnels through here.
from .._envelope import (
    EnvelopeOpts as _EnvelopeOpts,
    envelope_err as _envelope_err,
    envelope_ok as _envelope_ok,
    envelope_from_result as _envelope_from_result,
    finalize as _envelope_finalize,
    resolve_kind as _resolve_kind,
)
from .._spill import maybe_spill as _maybe_spill
from .._envelope import list_envelope as _list_envelope
from .._envelope import warn as _envelope_warn
# v0.29 provenance: every _guard/_guard_pure envelope gets stamped.
from .._provenance import stamp as _stamp_provenance


def _enrich_win32(msg: str) -> str:
    """Append a symbolic name after any 'gle=N' or 'status=0xN' in msg."""
    import re
    def _sub_dec(m: "re.Match[str]") -> str:
        n = int(m.group(1))
        name = _WIN32_ERRORS.get(n)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)
    def _sub_hex(m: "re.Match[str]") -> str:
        n = int(m.group(1), 16)
        name = _WIN32_ERRORS.get(n)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)
    msg = re.sub(r"gle=(\d+)", _sub_dec, msg)
    msg = re.sub(r"(?:status|nt|err)=0x([0-9a-fA-F]+)", _sub_hex, msg)
    return msg


def _addr(value: Any, name: str = "address") -> int:
    """Coerce an address from int OR hex/decimal string. Callers accept
    both because LLMs mistype 20-digit decimals — hex strings survive the
    round-trip losslessly. Empty/zero -> 0.

    Does NOT resolve `module+offset` notation — that needs a live client
    to look up module bases. Use `_addr_resolve` for the async version."""
    if value is None or value == "":
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        if "+" in s and not s.lower().startswith("0x"):
            raise ValueError(
                f"{name}: {value!r} looks like module+offset notation; "
                "use _addr_resolve() (call site must go through mem_rw / "
                "debug_manage / bp_manage which pass the client for lookup)")
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
        except ValueError as exc:
            raise ValueError(f"{name}: not a valid int or 0x-hex string: {value!r}") from exc
    raise TypeError(f"{name}: expected int or str, got {type(value).__name__}")


async def _addr_resolve(value: Any, client, *, kernel: bool = True,
                        pid: int = 0, name: str = "address") -> int:
    """Same as _addr but also accepts `module+offset` or `module.sys+0x…`.

    Looks up module base via `client.mem_modules(pid, kernel)`. The choice
    of kernel vs user list follows the space the caller is scanning: for
    kernel/physical addresses the module lives in the kernel module list,
    for user addresses it lives in the target process's module list.
    """
    if not isinstance(value, str) or "+" not in value:
        return _addr(value, name)
    s = value.strip()
    if s.lower().startswith("0x"):  # `0x…` may have `+` in comment; not us
        return _addr(value, name)
    mod, sep, off = s.partition("+")
    mod = mod.strip()
    off = off.strip()
    if not mod or not off:
        raise ValueError(f"{name}: {value!r} not valid module+offset notation")
    try:
        offset = int(off, 16) if off.lower().startswith("0x") else int(off, 0)
    except ValueError as exc:
        raise ValueError(f"{name}: offset {off!r} not a valid int/hex") from exc
    mod_l = mod.lower()
    mods = await client.mem_modules(pid, kernel)
    for m in mods:
        nm = str(m.get("name", "")).lower()
        pth = str(m.get("path", "")).lower()
        if nm == mod_l or pth.endswith("\\" + mod_l) or nm.startswith(mod_l):
            base = m.get("base")
            base_i = int(base) if isinstance(base, (int, str)) else 0
            return base_i + offset
    raise ValueError(
        f"{name}: module {mod!r} not found in "
        f"{'kernel' if kernel else 'pid=' + str(pid) + ' user'} module list "
        "(mem_rw(action='modules', filter=…) to browse; case-insensitive)")


def _unknown_action(tool: str, action: str, known: list[str],
                    help_map: dict[str, dict[str, str]] | None = None) -> str:
    """Standardized 'unknown action' error listing valid alternatives.

    ``help_map`` (the tool's ``*_ACTION_HELP`` dict, v0.28) inlines the
    per-verb one_liners into the error so a mistyped action answers
    "what should I have called?" in one round trip instead of pointing
    at a second discovery call. An empty ``action`` is treated as a
    help request outright — discovery needs no target connected."""
    if not (action or "").strip():
        return _actions_help(tool, help_map or {k: {} for k in known})
    msg = (f"unknown action {action!r} for {tool}; expected one of: "
           + ", ".join(sorted(known)))
    env = _envelope_err(msg, tool=tool, action=action)
    if isinstance(env.get("error"), dict):
        env["error"]["hint"] = (
            f"call {tool}(action='actions') for per-verb help "
            "(one_liner + key args + example per verb); "
            "target_manage(action='tool_index') lists every tool")
    if help_map:
        env["data"] = {
            "actions": {
                verb: str(spec.get("one_liner", ""))
                for verb, spec in sorted(help_map.items())
            },
        }
    return _j(env)


def _actions_help(tool: str, help_map: dict[str, dict[str, str]]) -> str:
    """Payload for the per-tool ``action='actions'`` verb (v0.22).

    Returns a legacy-shape dict ``{ok: true, actions: {verb: {one_liner,
    key_args, example}}, count, hint}`` — ``envelope_from_result`` wraps
    it under ``data`` with ``kind='actions'`` on the way out.

    Pure compute: call sites return this before ``require_client()`` so
    discovery works with no target connected. ``help_map`` is the
    per-tool ``*_ACTION_HELP`` dict; a verb missing from it falls back
    to empty strings so the verb still lists (the schema enum test
    catches drift, not this function).
    """
    return _j({
        "ok": True,
        "count": len(help_map),
        "actions": {
            verb: {
                "one_liner": spec.get("one_liner", ""),
                "key_args": spec.get("key_args", ""),
                "example": spec.get("example", ""),
            }
            for verb, spec in sorted(help_map.items())
        },
        "hint": (f"call {tool}(action='<verb>', ...); "
                 "target_manage(action='tool_index') lists every tool"),
    })


def _err(tool: str, action: str, exc: Exception, ctx: Context) -> str:
    """Legacy error helper — routes to the unified envelope. Kept for
    call sites that build errors outside `_guard` (e.g. mid-body validation
    that returns before `run()` resolves)."""
    return _j(_envelope_err(exc, tool=tool, action=action, ctx=ctx))


def _j_hex(data: Any) -> str:
    """Return-shape helper: JSON-encode data with every address/size field
    rendered as a '0x...' hex string (with `_int` mirror for arithmetic).
    Use for every tool response that touches driver-side data."""
    return _j(_hexify_dict(data))


def _j_hex_decoded(data: Any, context: str) -> str:
    """Like _j_hex() but also attaches enum-decoded siblings for the given
    context ('vad' | 'service' | 'handle' | 'pool' | 'region')."""
    return _j(_hexify_dict(_decode(data, context=context)))


# ------------------------------------------------------------- v0.18 breadcrumbs ----
# Best-effort helpers that write a tool_events row + upsert artifact rows
# after a real tool call succeeds. Every helper swallows its own errors
# because losing a breadcrumb is preferable to failing the underlying
# tool response.

def _sha256_file(path: str, chunk: int = 1 << 20) -> tuple[str, int]:
    """Return (sha256_hex, size_bytes) for a local file. On any error
    returns (`""`, `0`) — a caller writing a breadcrumb without a hash
    still gets a useful `module`-scoped event."""
    try:
        h = hashlib.sha256()
        n = 0
        with open(path, "rb") as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    break
                h.update(buf)
                n += len(buf)
        return h.hexdigest(), n
    except OSError:
        return "", 0


def _kind_from_ext(name: str) -> str:
    """Coarse artifact-kind classifier for the ``artifacts.kind`` column."""
    n = (name or "").lower()
    if n.endswith(".sys"):
        return "sys"
    if n.endswith(".dll"):
        return "dll"
    if n.endswith(".exe"):
        return "exe"
    if n.endswith(".dmp"):
        return "crashdump"
    if n.endswith(".i64") or n.endswith(".idb"):
        return "ida_db"
    return "bin"


def _register_dumped_module(ctx: "Context", dest: str, module: str,
                            kernel: bool) -> None:
    """Hook after `file_manage dump_module`: hash the file, upsert an
    artifact + alias, write a tool_event under the caller's client_id."""
    if not dest or not os.path.exists(dest):
        return
    sha, size = _sha256_file(dest)
    base = Path(dest).name
    alias = module.replace("\\", "/").split("/")[-1] or base
    cid = current_client_id()
    sid = ctx.get_current_session_id(cid) or ""
    if sha:
        ctx.ledger.upsert_artifact(
            sha, name=alias, kind=_kind_from_ext(alias), size=size,
            origin=("dump_module_kernel" if kernel else "dump_module_user"),
            alias=alias,
        )
    ctx.ledger.event(
        "file_manage", "dump_module", agent_id=cid, session_id=sid,
        artifact_sha=sha, module=alias,
        summary=f"{alias} → {dest} ({size} bytes, kernel={bool(kernel)})",
    )


# Analysis-session name -> (sha256, on_disk_path) cache, populated on
# open. ida_manage/ghidra_manage passthrough actions (decompile,
# rename_function, …) look up the sha via the session name so their
# breadcrumbs land on the same artifact row without an extra hash pass.
# Keys are prefixed ``<engine>:`` so an IDA and a Ghidra session sharing
# a friendly name never cross-wire their artifact rows.
_IDA_SESSION_SHA_CACHE: dict[str, tuple[str, str]] = {}


def _session_row_key(engine: str, session_name: str) -> str:
    """Ledger `ida_sessions` PK for an analysis session.

    IDA sessions keep the bare name (pre-engine rows/tests expect it);
    other engines get an ``engine:`` prefix so an IDA ``tcpip`` and a
    Ghidra ``tcpip`` never clobber each other's row. `about()` shows
    the prefix — provenance is visible, not a collision.
    """
    return session_name if engine == "ida" else f"{engine}:{session_name}"


def _register_ida_open(ctx: "Context", session_name: str, path: str,
                       async_open: bool, engine: str = "ida") -> None:
    """Hook after `*_manage open`/`open_async` succeeds. Best-effort."""
    if not session_name:
        return
    tool = f"{engine}_manage"
    sha, size = _sha256_file(path) if path and os.path.exists(path) else ("", 0)
    alias = Path(path).name if path else session_name
    cid = current_client_id()
    sid = ctx.get_current_session_id(cid) or ""
    if sha:
        ctx.ledger.upsert_artifact(
            sha, name=alias, kind=_kind_from_ext(alias), size=size,
            origin=f"{engine}_open", alias=alias,
        )
        # remember the mapping for later passthrough events
        _IDA_SESSION_SHA_CACHE[f"{engine}:{session_name}"] = (sha, path or "")
    ctx.ledger.open_ida_session(
        _session_row_key(engine, session_name),
        artifact_sha=sha, opened_by_agent=cid,
        on_disk_path=path or "", engine=engine,
    )
    ctx.ledger.event(
        tool, "open_async" if async_open else "open",
        agent_id=cid, session_id=sid, artifact_sha=sha, module=alias,
        summary=f"session={session_name} path={path}",
    )


def _register_ida_close(ctx: "Context", session_name: str,
                        engine: str = "ida") -> None:
    if not session_name:
        return
    tool = f"{engine}_manage"
    ctx.ledger.close_ida_session(_session_row_key(engine, session_name))
    cid = current_client_id()
    sha = _IDA_SESSION_SHA_CACHE.get(f"{engine}:{session_name}", ("", ""))[0]
    ctx.ledger.event(
        tool, "close", agent_id=cid, artifact_sha=sha,
        summary=f"session={session_name}",
    )
    _IDA_SESSION_SHA_CACHE.pop(f"{engine}:{session_name}", None)


def _register_ida_action(ctx: "Context", session_name: str, action: str,
                         args: dict[str, Any] | None,
                         engine: str = "ida") -> None:
    """Hook after every non-open/close passthrough (decompile,
    rename_function, set_comment, list_imports, …). Kept tight — one
    row per call, summary trimmed."""
    if not session_name:
        return
    tool = f"{engine}_manage"
    sha, _ = _IDA_SESSION_SHA_CACHE.get(f"{engine}:{session_name}", ("", ""))
    # pull one primary arg for the summary
    primary = ""
    if isinstance(args, dict):
        for k in ("function_address", "start_address", "address",
                  "new_name", "name", "function_name", "variable_name",
                  "filter", "query"):
            v = args.get(k)
            if v:
                primary = f"{k}={v}"; break
    summary = f"{action}({primary}) session={session_name}"
    cid = current_client_id()
    ctx.ledger.event(
        tool, action, agent_id=cid, artifact_sha=sha,
        summary=summary[:400],
    )
    ctx.ledger.touch_ida_session(_session_row_key(engine, session_name))


def _pattern_scan_breadcrumb(ctx: "Context", *, pattern: str, space: str,
                             address: Any, size: int, module: str = "") -> None:
    """Hook after `mem_rw pattern_scan` / `scan_start` succeeds."""
    cid = current_client_id()
    addr_s = f"0x{address:x}" if isinstance(address, int) else str(address or "")
    ctx.ledger.event(
        "mem_rw", "pattern_scan", agent_id=cid, module=module,
        address=addr_s,
        summary=f"space={space} pattern={pattern!r} size={size}",
    )


def _script_run_breadcrumb(ctx: "Context", *, name: str, target: str,
                           params_json: str) -> None:
    cid = current_client_id()
    trunc = params_json if len(params_json) < 200 else params_json[:197] + "..."
    ctx.ledger.event(
        "script_manage", "run", agent_id=cid, target=target,
        summary=f"{name}({trunc})",
    )


async def _merge_driver_state(ctx: Context, result: dict, verb: str,
                              view: str = "") -> dict:
    """v0.16: after driver_load / driver_unload, follow up with one status()
    probe and merge driver_state / driver_present / driver_version into the
    response envelope so callers don't need a second round-trip to know
    whether the SCM operation actually took effect.

    The status probe is best-effort: if it fails we still return the RPC's
    result unchanged. Failures at this layer would just mean an extra
    status call for the caller — we don't want to mask the load/unload
    result behind a status-probe error.
    """
    if not isinstance(result, dict):
        return result
    try:
        client = ctx.session.require_client(view)
    except Exception:
        return result
    try:
        st = await client.status()
    except Exception as exc:
        result.setdefault("driver_state_probe_error", f"{type(exc).__name__}: {exc}")
        return result
    driver_state = st.get("driver_state")
    if driver_state is not None:
        result.setdefault("driver_state", driver_state)
    ds_upper = str(driver_state or "").upper()
    driver_present = ds_upper in ("LOADED", "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED",
                                   "SERVICE", "MANUAL_MAPPED")
    result.setdefault("driver_present", driver_present)
    if "driver_version" in st:
        result.setdefault("driver_version", st.get("driver_version"))
    if "service_state" in st:
        result.setdefault("service_state", st.get("service_state"))
    result.setdefault("verb", verb)
    return result


async def _require_driver(ctx: Context, tool: str, action: str,
                          name: str = "") -> dict | None:
    """Preflight check for actions that need the kernel driver loaded.

    Returns an error envelope dict (to be _j()'d and returned) if the driver
    isn't up; returns None to signal "OK to proceed". Every driver-dependent
    action calls this as its first line so the LLM gets a clean, actionable
    error instead of a deep gRPC failure."""
    try:
        c = ctx.session.require_client(name) if name else ctx.session.require_client()
    except Exception as exc:
        return {"ok": False, **_enrich_error(tool, action, f"no target connected: {exc}"),
                "kind": "no_target",
                "hint": "run target_manage(action='connect') first"}
    try:
        st = await c.status()
    except Exception as exc:
        return {"ok": False, **_enrich_error(tool, action, str(exc)),
                "kind": "status_probe_failed",
                "hint": "check target_manage(action='status')"}
    ds = str(st.get("driver_state", ""))
    # driver_state is a string on the LLM side; the v0.10 driver-absent
    # envelope wraps each flag as {value, confidence, source}. Accept both
    # legacy scalars and the new envelope shape.
    if ds and ds not in ("loaded", "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED"):
        driver_present = bool(st.get("driver_present", False))
        if not driver_present:
            return {"ok": False,
                    "error": f"{tool} {action}: driver not loaded on target (state={ds!r})",
                    "kind": "driver_absent",
                    "hint": "run target_manage(action='driver_load') and retry; "
                            "check target_manage(action='status') to confirm "
                            "driver_state == 'loaded'",
                    "tool": tool, "action": action}
    return None


# --- Filter / summary helpers for mem_rw list-returning actions ------------
def _modules_summary(rows: list[dict]) -> dict:
    by_signer: dict[str, int] = {}
    total_size = 0
    for r in rows:
        signer = str(r.get("signer") or r.get("path") or "unknown")
        by_signer[signer] = by_signer.get(signer, 0) + 1
        try:
            total_size += int(r.get("size", 0)) if not isinstance(r.get("size"), str) \
                          else int(r.get("size", "0"), 0)
        except Exception:
            pass
    return {"total": len(rows), "by_signer": by_signer, "total_size": total_size}


def _apply_modules_filter(rows: list[dict], f: dict) -> list[dict]:
    import re, fnmatch
    out = rows
    if f.get("name_regex"):
        pat = re.compile(f["name_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("name", "")))]
    if f.get("name_glob"):
        gl = str(f["name_glob"]).lower()
        out = [r for r in out
                if fnmatch.fnmatch(str(r.get("name", "")).lower(), gl)]
    if f.get("min_size"):
        min_size = int(f["min_size"])
        def _sz(r):
            s = r.get("size", 0)
            return int(s, 0) if isinstance(s, str) else int(s)
        out = [r for r in out if _sz(r) >= min_size]
    if f.get("path_contains"):
        s = str(f["path_contains"]).lower()
        out = [r for r in out if s in str(r.get("path", "")).lower()]
    return out


def _vad_summary(rows: list[dict]) -> dict:
    from .._decode_enums import decode_protect, decode_vad_type
    by_protect: dict[str, int] = {}
    by_vad_type: dict[str, int] = {}
    total_commit = 0
    for r in rows:
        p = decode_protect(r.get("protect", 0))
        v = decode_vad_type(r.get("vad_type", 0))
        by_protect[p] = by_protect.get(p, 0) + 1
        by_vad_type[v] = by_vad_type.get(v, 0) + 1
        try:
            total_commit += int(r.get("commit_charge", 0))
        except Exception:
            pass
    return {"total": len(rows), "by_protect": by_protect,
            "by_vad_type": by_vad_type, "total_commit_charge": total_commit}


def _apply_vad_filter(rows: list[dict], f: dict) -> list[dict]:
    from .._decode_enums import decode_protect
    out = rows
    if f.get("protect"):
        want = f["protect"]
        wants = set(want) if isinstance(want, list) else {want}
        # Accept both the raw int and the decoded string.
        wants_upper = {str(x).upper() for x in wants}
        def _matches_protect(r):
            raw = r.get("protect", 0)
            dec = decode_protect(raw).upper()
            return (str(raw) in wants_upper or hex(int(raw) if not isinstance(raw, str)
                                                    else int(raw, 0)).upper() in wants_upper
                    or any(w in dec for w in wants_upper))
        out = [r for r in out if _matches_protect(r)]
    if f.get("vad_type") is not None:
        vt = f["vad_type"]
        wants = {int(x) for x in (vt if isinstance(vt, list) else [vt])}
        out = [r for r in out if int(r.get("vad_type", 0)) in wants]
    if f.get("min_size"):
        min_size = int(f["min_size"])
        def _extent(r):
            s = int(r.get("start", 0), 0) if isinstance(r.get("start"), str) else int(r.get("start", 0))
            e = int(r.get("end", 0), 0) if isinstance(r.get("end"), str) else int(r.get("end", 0))
            return max(0, e - s)
        out = [r for r in out if _extent(r) >= min_size]
    return out


def _handles_summary(rows: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for r in rows:
        t = str(r.get("type_name") or r.get("type") or "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(rows), "by_type": by_type}


def _apply_handles_filter(rows: list[dict], f: dict) -> list[dict]:
    import re
    out = rows
    if f.get("type_name"):
        want = f["type_name"]
        wants = {str(x).lower() for x in (want if isinstance(want, list) else [want])}
        out = [r for r in out if str(r.get("type_name", "")).lower() in wants]
    if f.get("name_regex"):
        pat = re.compile(f["name_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("name", "")))]
    if f.get("name_substring"):
        s = str(f["name_substring"]).lower()
        out = [r for r in out if s in str(r.get("name", "")).lower()]
    if f.get("granted_access_and"):
        mask = int(f["granted_access_and"])
        out = [r for r in out if (int(r.get("granted_access", 0)) & mask) == mask]
    return out


def _processes_summary(rows: list[dict]) -> dict:
    by_parent: dict[int, int] = {}
    for r in rows:
        pp = int(r.get("parent_pid", 0))
        by_parent[pp] = by_parent.get(pp, 0) + 1
    return {"total": len(rows), "by_parent": by_parent}


def _apply_processes_filter(rows: list[dict], f: dict) -> list[dict]:
    import re
    out = rows
    if f.get("image_regex"):
        pat = re.compile(f["image_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("image_name", "")))]
    if f.get("parent_pid") is not None:
        pp = int(f["parent_pid"])
        out = [r for r in out if int(r.get("parent_pid", 0)) == pp]
    if f.get("pid_range"):
        lo, hi = f["pid_range"]
        out = [r for r in out if int(lo) <= int(r.get("pid", 0)) <= int(hi)]
    return out


# --- Phase 1 codegen: disasm / assemble helpers ---------------------------
#
# Both actions are dispatched by mem_rw. They live at module scope so tests
# can import them directly without spinning up the whole FastMCP server.


def _codegen_extra_err(exc: Exception) -> str:
    """Turn a CodegenUnavailable into the standard {ok:false, kind, ...} envelope."""
    from ...codegen import CodegenUnavailable
    if isinstance(exc, CodegenUnavailable):
        return _j({"ok": False, "kind": exc.kind, "error": str(exc),
                   "hint": exc.hint})
    # Bad-arg variants carry `.kind`/`.hint` attributes too.
    kind = getattr(exc, "kind", None) or "internal"
    hint = getattr(exc, "hint", "") or ""
    return _j({"ok": False, "kind": kind,
               "error": f"{type(exc).__name__}: {exc}",
               "hint": hint})


def _annotate_symbols(instructions: list[dict[str, Any]],
                      mods: list[dict[str, Any]]) -> None:
    """Best-effort: for every op_str that mentions a 0x... constant, if the
    value falls inside one of the mods, append ``module+offset`` alongside
    the raw value in a new ``sym`` field. Non-destructive to op_str.
    """
    if not mods or not instructions:
        for ins in instructions:
            ins.setdefault("sym", None)
        return

    # Build a sorted (base, size, name) table for O(log n) lookups.
    rows: list[tuple[int, int, str]] = []
    for m in mods:
        b = m.get("base", 0)
        s = m.get("size", 0)
        try:
            base_i = int(b, 0) if isinstance(b, str) else int(b)
            size_i = int(s, 0) if isinstance(s, str) else int(s)
        except Exception:
            continue
        if base_i and size_i:
            rows.append((base_i, size_i, str(m.get("name") or "")))
    rows.sort()

    def _lookup(va: int) -> str | None:
        # Linear scan is fine for typical module counts (< 500). If this
        # ever becomes hot, swap for bisect over (base, base+size).
        for base_i, size_i, nm in rows:
            if base_i <= va < base_i + size_i:
                return f"{nm}+0x{va - base_i:x}"
            if base_i > va:
                break
        return None

    import re as _re
    hex_pat = _re.compile(r"0x([0-9a-fA-F]+)")
    for ins in instructions:
        found = None
        for m in hex_pat.finditer(str(ins.get("op_str", ""))):
            try:
                va = int(m.group(1), 16)
            except ValueError:
                continue
            sym = _lookup(va)
            if sym is not None:
                found = sym
                break
        ins["sym"] = found


async def _mem_disasm(ctx: Context, *, name: str, pid: int, space: str,
                       address: int, bytes_hex: str,
                       arch: str, syntax: str, count: int, size: int,
                       detail: bool, resolve_symbols: bool,
                       allow_fault: bool, timeout_s: float) -> str:
    """Dispatch handler for ``mem_rw(action='disasm')``."""
    from ...codegen import disasm as _disasm

    # Cap the caller-supplied count/size to keep responses bounded.
    max_count = min(int(count or 64), 4096)
    max_size = min(int(size or (max_count * 15)), 64 * 1024)

    truncated = False
    first_bad = 0
    source = "buffer"
    payload: bytes = b""

    if bytes_hex:
        try:
            payload = bytes.fromhex(bytes_hex.replace(" ", "").replace(",", ""))
        except ValueError as exc:
            return _j({"ok": False,
                       "error": f"disasm: bytes_hex not valid hex: {exc}",
                       "kind": "bad_arg"})
    else:
        if not address:
            return _j({"ok": False,
                       "kind": "bad_arg",
                       "error": "disasm: supply either bytes_hex or address"})
        source = "target"
        try:
            c = ctx.session.require_client(name)
        except Exception as exc:
            return _j({"ok": False, "kind": "no_target",
                       "error": f"disasm: no target connected: {exc}",
                       "hint": "target_manage(action='connect') first, "
                               "or pass bytes_hex for pure-compute disasm"})
        # Attempt partial read for graceful truncation on unmapped pages.
        try:
            got = await c.mem_read(pid, address, max_size, space,
                                    allow_fault=allow_fault,
                                    partial=True, want_meta=True,
                                    timeout=timeout_s or None)
            if isinstance(got, tuple):
                payload, meta = got
                first_bad = int(meta.get("first_bad_offset", 0))
                if int(meta.get("read_bytes", len(payload))) < max_size:
                    truncated = True
            else:
                payload = got
        except TypeError:
            # Older client stub without partial/want_meta support.
            payload = await c.mem_read(pid, address, max_size, space,
                                        allow_fault=allow_fault,
                                        timeout=timeout_s or None)
        except Exception as exc:
            return _j({"ok": False, "kind": "read_failed",
                       "error": f"disasm: mem_read failed: {exc}",
                       "hint": _enrich_win32(str(exc))})

    if not payload:
        return _j({"ok": True, "arch": arch, "start": hex(address),
                   "instructions": [], "bytes_used": 0,
                   "truncated": truncated, "source": source})

    try:
        instructions = _disasm(payload, arch,
                                syntax=syntax,
                                address=int(address or 0),
                                count=max_count,
                                detail=detail)
    except Exception as exc:
        return _codegen_extra_err(exc)

    bytes_used = sum(int(i.get("size", 0)) for i in instructions)
    if bytes_used < len(payload):
        truncated = True

    if resolve_symbols and source == "target":
        try:
            c = ctx.session.require_client(name)
            use_kernel = space in ("kernel", "physical")
            mods = await c.mem_modules(pid, use_kernel)
            _annotate_symbols(instructions, mods)
        except Exception:
            for ins in instructions:
                ins.setdefault("sym", None)
    else:
        for ins in instructions:
            ins.setdefault("sym", None)

    out = {"ok": True, "arch": arch, "start": hex(int(address or 0)),
           "instructions": instructions,
           "bytes_used": bytes_used,
           "truncated": truncated,
           "source": source}
    if first_bad:
        out["first_bad_offset"] = first_bad
    return _j_hex(out)


async def _mem_assemble(ctx: Context, *, name: str, pid: int, space: str,
                         code: str, arch: str, address: int,
                         write_to: int | str, dry_run: bool,
                         allow_map_write: bool) -> str:
    """Dispatch handler for ``mem_rw(action='assemble')``."""
    from ...codegen import assemble as _assemble, disasm as _disasm, AssembleError

    if not code or not str(code).strip():
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "assemble: `code` is required"})

    # Write-target coercion.
    write_addr = 0
    if write_to:
        try:
            write_addr = _addr(write_to, name="write_to")
        except Exception as exc:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"assemble: bad write_to: {exc}"})

    # Refuse to silently write to a target when the caller left dry_run
    # at its default. The plan explicitly calls out this as `unsafe_default`.
    if write_addr and dry_run:
        return _j({"ok": False, "kind": "unsafe_default",
                   "error": "assemble: write_to set but dry_run=true; "
                            "set dry_run=false to authorize the write",
                   "hint": "dry_run=true assembles + returns bytes without "
                           "touching the target"})

    try:
        encoded, ins_count, labels = _assemble(code, arch,
                                                address=int(address or write_addr or 0))
    except AssembleError as exc:
        return _j({"ok": False, "kind": exc.kind,
                   "error": str(exc),
                   "hint": exc.hint,
                   "count": exc.count})
    except Exception as exc:
        return _codegen_extra_err(exc)

    # Round-trip through disasm so the caller sees exactly what the CPU sees.
    try:
        roundtrip = _disasm(encoded, arch,
                             address=int(address or write_addr or 0),
                             count=max(1, ins_count) * 2 + 8)
    except Exception:
        roundtrip = []

    resp: dict[str, Any] = {
        "ok": True,
        "bytes_hex": encoded.hex(),
        "size": len(encoded),
        "ins_count": ins_count,
        "dry_run": bool(dry_run),
        "roundtrip": roundtrip,
    }
    if labels:
        resp["labels"] = {k: hex(v) for k, v in labels.items()}

    if write_addr and not dry_run:
        if space == "user" and not pid:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "assemble+write: user-space write requires "
                                "pid=<target>; use space='kernel' for kernel "
                                "VAs"})
        try:
            c = ctx.session.require_client(name)
        except Exception as exc:
            return _j({"ok": False, "kind": "no_target",
                       "error": f"assemble+write: no target connected: {exc}"})
        try:
            written = await c.mem_write(pid, write_addr, encoded, space,
                                         allow_map_write=allow_map_write)
        except Exception as exc:
            return _j({"ok": False, "kind": "write_failed",
                       "error": f"assemble+write: mem_write failed: {exc}",
                       "hint": _enrich_win32(str(exc)),
                       "bytes_hex": encoded.hex(), "size": len(encoded)})
        resp["written"] = int(written)
        resp["write_to"] = hex(write_addr)

    return _j_hex(resp)


def _coerce_to_envelope(result: Any, *, tool: str, action: str,
                        kind: str | None, elapsed_ms: int | None) -> dict:
    """Turn a tool `run()` result (str/dict/list/scalar) into a v0.14 envelope.

    Handles the transitional shapes tool bodies still emit:
      * `_j(...)`-produced JSON strings (parsed back to a dict).
      * Legacy `{ok: False, error: "..."}` dicts (routed via envelope_err).
      * Legacy success dicts (wrapped under `data`).
    Once every tool body builds envelopes directly, this coercion is dead
    weight and gets removed."""
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return _envelope_ok(
                {"text": result},
                kind=_resolve_kind(tool, action, kind),
                tool=tool, action=action, elapsed_ms=elapsed_ms,
            )
        result = parsed
    return _envelope_from_result(
        result, tool=tool, action=action, kind=kind, elapsed_ms=elapsed_ms,
    )


def _opts_from_args(args: dict[str, Any] | None) -> _EnvelopeOpts:
    """Build finalize options from the tool call's own kwargs so a caller's
    ``verbosity`` / ``include_*`` / ``fields`` / ``max_bytes`` actually drive
    response shaping (row-collapse, mirror strips, projection, spill budget).

    Before this, ``_guard`` emitted with ``opts=None`` and ``finalize`` always
    ran at the hard-coded default ``verbosity="normal"`` — the per-call
    ``verbosity`` kwarg on every tool was silently ignored, so there was no
    way to opt into ``compact`` (or back out to ``full``/``raw``) through the
    live tool path. Unknown/missing keys fall back to the EnvelopeOpts
    defaults; a bad ``verbosity`` string degrades to ``normal``."""
    a = args or {}
    verb = str(a.get("verbosity") or "normal")
    if verb not in ("compact", "normal", "full", "raw"):
        verb = "normal"
    fields = a.get("fields") if isinstance(a.get("fields"), list) else []
    try:
        max_bytes = int(a.get("max_bytes") or 0)
    except (TypeError, ValueError):
        max_bytes = 0
    return _EnvelopeOpts(
        verbosity=verb,
        max_bytes=max_bytes,
        fields=[str(f) for f in fields],
        filter=a.get("filter") or "",
        include_ascii=bool(a.get("include_ascii")),
        include_int=bool(a.get("include_int")),
        include_decoded=bool(a.get("include_decoded")),
    )


def _emit(env: dict, *, ctx: Context | None = None,
          opts: _EnvelopeOpts | None = None,
          request: dict | None = None) -> str:
    """Final step: finalize (hex/decode/size), auto-spill oversize payloads,
    then JSON-encode. Every envelope produced by _guard / _guard_pure funnels
    through here on its way out.

    Spill is skipped when ctx is None (the pure builders in tests) or when
    the caller passed `verbosity="raw"` / `max_bytes=-1`.

    Part 3: `request` (the post-binding args from _guard) feeds the
    evidence retention on spill — None on legacy call sites, which keep
    the exact pre-evidence behavior."""
    _envelope_finalize(env, opts=opts)
    if ctx is not None and env.get("kind") != "error":
        cfg = ctx.cfg
        budget = int(opts.max_bytes) if (opts and opts.max_bytes) else cfg.mcp_max_bytes()
        if budget > 0:
            # Evidence retention wiring (Part 3): stub cfgs (tests) may
            # not implement artifacts_dir — then no retention happens.
            _art_dir = getattr(cfg, "artifacts_dir", None)
            _maybe_spill(
                env,
                budget_bytes=budget,
                spill_dir=cfg.spill_dir(),
                preview_bytes=cfg.mcp_preview_bytes(),
                artifacts_root=_art_dir() if callable(_art_dir) else None,
                ledger=getattr(ctx, "ledger", None),
                request=request,
            )
            # Refresh size_bytes after spill.
            try:
                env.setdefault("summary", {})["size_bytes"] = len(
                    json.dumps(env, default=str)
                )
            except (TypeError, ValueError):
                pass
    if ctx is not None and env.get("kind") != "error":
        _retain_inventory_from_env(ctx, env)
    return _j(env)


# (tool, action) -> (completion kind, candidate name fields). When one of
# these actions returns successfully, its row names are stashed on the
# Context so the MCP `completion/complete` handler can suggest them later
# (completions._retained reads ctx._retained_inventories[kind]). An EMPTY
# stash still means "nothing retained", never "does not exist".
_INVENTORY_PRODUCERS: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("mem_rw", "modules"):        ("module", ("name",)),
    ("mem_rw", "obj_enum"):       ("device", ("name", "path")),
    ("symbols_manage", "enum_info"): ("symbol", ("name",)),
}

# Cap retained names per kind so a huge enumeration can't grow the Context
# without bound; completion caps at 100 anyway.
_RETAIN_CAP = 500


def _retain_inventory_from_env(ctx: "Context", env: dict) -> None:
    """Best-effort: stash row names from an inventory-producing action so
    argument completion can suggest them. Never raises — a shape it does
    not recognize (spilled payload, scalar result) is simply skipped."""
    spec = _INVENTORY_PRODUCERS.get((env.get("tool"), env.get("action")))
    if spec is None:
        return
    kind, name_fields = spec
    data = env.get("data")
    rows = data.get("items") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return  # summary=true / spilled payload / unexpected shape
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for f in name_fields:
            v = row.get(f)
            if v:
                names.append(str(v))
                break
    if not names:
        return
    try:
        store = getattr(ctx, "_retained_inventories", None)
        if not isinstance(store, dict):
            store = {}
            ctx._retained_inventories = store
        store[kind] = names[:_RETAIN_CAP]
    except Exception:  # noqa: BLE001 — retention is pure DX, never fatal
        pass


def _resolve_stamp(ctx: "Context", args: dict) -> dict | None:
    """Best-effort `session.target_stamp` for the call's ``name=`` arg —
    None on any failure (older test doubles have no ``target_stamp``)."""
    name = str((args or {}).get("name") or "")
    try:
        return ctx.session.target_stamp(name) if ctx.session else None
    except Exception:
        return None


def _stamp_target(env: dict, ctx: "Context", args: dict) -> dict:
    """Attach the v0.30 minimal identity stamp: a BARE view key
    ('lab2.kernel'), and only when the answer could be attributed to the
    wrong box (more than one view connected, or not the caller's focus
    machine — see Session.stamp_needed). Single-view sessions carry no
    stamp at all. Full machine identity (trust/purpose/notes/endpoints)
    arrives once per machine on first connect (machine_info) and on
    demand via target_manage(action='machines')."""
    sess = getattr(ctx, "session", None)
    if sess is None:
        return env
    name = str((args or {}).get("name") or "")
    try:
        key = sess.resolve_view_name(name)
        if not key or key not in sess.clients:
            return env
        if not sess.stamp_needed(key):
            return env
        env.setdefault("target", key)
    except Exception:
        return env
    return env


# v0.30: actuator verbs checked against machine trust (registry / machines:
# metadata) when security.min_trust_actuator is raised above "untrusted".
_ACTUATOR_PAIRS = frozenset({
    ("device_manage", "ioctl"),
    ("target_manage", "driver_load"),
    ("target_manage", "driver_unload"),
    ("target_manage", "boot_recover"),
    ("exec_manage", "kill_process"),
    ("exec_manage", "call"),
})


def _check_actuator_trust(ctx: "Context", tool: str, action: str,
                          args: dict) -> None:
    """Machine-trust gate for actuator verbs. Config default
    ('untrusted') disables it entirely; otherwise a machine below
    security.min_trust_actuator is refused unless the call carries
    force=true. Reads are never gated and never annotated."""
    if (tool, action) not in _ACTUATOR_PAIRS:
        return
    if bool((args or {}).get("force")):
        return
    min_trust = str(getattr(ctx.cfg.security, "min_trust_actuator", "untrusted")
                    or "untrusted").strip().lower()
    if min_trust in ("", "untrusted"):
        return
    sess = getattr(ctx, "session", None)
    if sess is None:
        return
    name = str((args or {}).get("name") or (args or {}).get("machine") or "")
    try:
        key = sess.resolve_view_name(name)
        machine = sess.machine_of(key)
    except Exception:
        machine = name.strip() or "<unknown>"
    try:
        trust = str(ctx.registry.trust_for(machine) or "untrusted").lower()
    except Exception:
        trust = "untrusted"
    from ...config import TRUST_LEVELS
    if TRUST_LEVELS.get(trust, 0) < TRUST_LEVELS.get(min_trust, 0):
        raise TargetNotAllowedError(
            f"{tool}.{action} on machine {machine!r} refused: trust={trust} "
            f"< security.min_trust_actuator={min_trust} — pass force=true "
            "to override, target_manage(action='machines_set', "
            "trust=...) to regrade the machine, or lower the config knob")


async def _guard(ctx: Context, tool: str, action: str, args: dict[str, Any],
                 fn, *, kind: str | None = None) -> str:
    """Every `@mcp.tool` action funnels through here. Runs the allowlist
    gate, executes fn(), and wraps the result in the unified v0.14 envelope
    (see `_envelope.py`). Exceptions become nested `{error: {error, kind,
    hint}}` failures via `envelope_err`.

    `kind` is the envelope's shape discriminator. Omit to derive from the
    action name (see `KIND_OVERRIDES` in `_envelope.py` for cross-tool
    aliases like `mem_rw|debug_manage|emulate_manage` -> kind="read").
    """
    import time as _time
    started = _time.monotonic()
    try:
        _check_actuator_trust(ctx, tool, action, args)
        ctx.session.assert_allowed(tool, action, args)
        result = await fn()
        # v0.27: resolve the view key lazily AFTER fn() — a connect's
        # name= is a *new* view that doesn't exist before the call.
        logged_args = dict(args) if args else {}
        stamp = _resolve_stamp(ctx, logged_args)
        if stamp:
            logged_args["_view"] = stamp["view"]
        ctx.session.record_tool_call(tool, action, args=logged_args, ok=True)
    except (PermissionError, TargetNotAllowedError, IdaBridgeError,
            GhidraBridgeError, PluginError) as exc:
        return _emit(_stamp_target(
            _stamp_provenance(_envelope_err(exc, tool=tool, action=action,
                                            ctx=ctx, received_args=args),
                              tool, action), ctx, args), ctx=ctx)
    except Exception as exc:
        if isinstance(exc, AmbiguousTargetError):
            env = _envelope_err(exc, tool=tool, action=action, ctx=ctx,
                                received_args=args)
            env["kind"] = exc.kind
            env["machines"] = exc.machines
            env.setdefault("error", {})
            if isinstance(env["error"], dict):
                env["error"]["kind"] = exc.kind
                env["error"].setdefault("hint", exc.hint)
            # No view resolved — _stamp_target returns env unchanged.
            return _emit(_stamp_target(_stamp_provenance(env, tool, action),
                                       ctx, args), ctx=ctx)
        return _emit(_stamp_target(
            _stamp_provenance(_envelope_err(exc, tool=tool, action=action,
                                            ctx=ctx, received_args=args),
                              tool, action), ctx, args), ctx=ctx)
    elapsed_ms = int((_time.monotonic() - started) * 1000)
    return _emit(
        _stamp_target(
            _stamp_provenance(
                _coerce_to_envelope(
                    result, tool=tool, action=action, kind=kind,
                    elapsed_ms=elapsed_ms,
                ), tool, action),
            ctx, args),
        ctx=ctx,
        opts=_opts_from_args(args),
        request=args,
    )


async def _guard_pure(ctx: Context, tool: str, action: str,
                      args: dict[str, Any], fn, *, kind: str | None = None) -> str:
    """Like _guard but skips assert_allowed — pure-compute tools have no
    target, so the allowlist gate is meaningless. Errors surface through the
    same unified v0.14 envelope."""
    import time as _time
    from ..conversions import ConversionError
    started = _time.monotonic()
    try:
        result = await fn()
        ctx.session.record_tool_call(tool, action, args=args, ok=True)
    except ConversionError as exc:
        # ConversionError carries its own {kind, hint}; preserve them by
        # constructing the envelope directly rather than going through
        # `enrich_error` (which classifies from the raw string).
        ctx.session.record_tool_call(tool, action, ok=False, error=str(exc))
        env = {
            "ok": False,
            "kind": "error",
            "tool": tool,
            "action": action,
            "error": {"error": str(exc), "kind": exc.kind, "hint": exc.hint},
        }
        return _emit(_stamp_provenance(env, tool, action), ctx=ctx)
    except Exception as exc:
        return _emit(_stamp_provenance(
            _envelope_err(exc, tool=tool, action=action, ctx=ctx,
                          received_args=args), tool, action), ctx=ctx)
    elapsed_ms = int((_time.monotonic() - started) * 1000)
    return _emit(
        _stamp_provenance(
            _coerce_to_envelope(
                result, tool=tool, action=action, kind=kind,
                elapsed_ms=elapsed_ms,
            ), tool, action),
        ctx=ctx,
        request=args,
    )


def _ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:256])


__all__ = [
    'AmbiguousTargetError',
    'AgentClient',
    'Annotated',
    'Any',
    'BaseModel',
    'BusyInfo',
    'Context',
    'FastMCP',
    'Field',
    'FindingsLedger',
    'GhidraBridge',
    'GhidraBridgeError',
    'IdaBridge',
    'IdaBridgeError',
    'LeaseHandle',
    'LeaseManager',
    'OwnershipRegistry',
    'PRIMARY_TARGET',
    'Path',
    'PluginError',
    'READONLY_FALSE',
    'READONLY_TRUE',
    'Session',
    'TargetNotAllowedError',
    'ToolAnnotations',
    '_EnvelopeOpts',
    '_IDA_SESSION_SHA_CACHE',
    '_WIN32_ERRORS',
    '_addr',
    '_addr_resolve',
    '_annotate_symbols',
    '_apply_handles_filter',
    '_apply_modules_filter',
    '_apply_processes_filter',
    '_apply_vad_filter',
    '_ascii',
    '_actions_help',
    '_classify',
    '_codegen_extra_err',
    '_coerce_to_envelope',
    '_decode',
    '_decode_list',
    '_emit',
    '_enrich_error',
    '_enrich_win32',
    '_enrich_win32_v2',
    '_envelope_err',
    '_envelope_finalize',
    '_envelope_from_result',
    '_envelope_ok',
    '_envelope_warn',
    '_err',
    '_filter_ida_schemas',
    '_guard',
    '_guard_pure',
    '_handles_summary',
    '_hexify',
    '_hexify_dict',
    '_j',
    '_j_hex',
    '_j_hex_decoded',
    '_kind_from_ext',
    '_list_envelope',
    '_maybe_spill',
    '_mem_assemble',
    '_mem_disasm',
    '_merge_driver_state',
    '_modules_summary',
    '_one_line_desc',
    '_parse_ida_schemas_filter',
    '_pattern_scan_breadcrumb',
    '_processes_summary',
    '_register_dumped_module',
    '_register_ida_action',
    '_register_ida_close',
    '_register_ida_open',
    '_require_driver',
    '_resolve_kind',
    '_resolve_stamp',
    '_script_run_breadcrumb',
    '_session_row_key',
    '_sha256_file',
    '_stamp_target',
    '_unknown_action',
    '_vad_summary',
    'annotations',
    'asyncio',
    'current_client_id',
    'discover',
    'file_result',
    'format_report',
    'hashlib',
    'json',
    'log',
    'logging',
    'meta_dict',
    'os',
    'run_parity',
    'run_plugin',
    'struct',
    'verdict',
]
