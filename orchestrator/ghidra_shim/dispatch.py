"""Tool-call dispatch: passthrough with auto-promotion + oversized-result
auto-chunking, plus the ``ghidra_job_*`` / ``ghidra_result`` shim tools.

Port of ``idalib_shim.dispatch``. Two Ghidra-specific deviations:

* Every passthrough call resolves its ``database`` arg to a session and
  injects ``binary_name=<program>`` — the shared backend multiplexes on
  that argument where the idalib backend implied it per-process.
* The decompile-failure fallback uses ``disassemble_function`` with an
  ``address`` arg (our backend's spelling) and the nearest-function
  enrichment reads ``ghidra_query_context``.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid

import mcp.types as types

from ghidra_shim_ergo import (
    apply_arg_aliases as _apply_arg_aliases,
    compute_nearest_function as _compute_nearest_function,
)

from .envelopes import _chunked_envelope, _pending_envelope
from .jobs import (
    CHUNK_BYTES,
    JOBS,
    JOBS_LOCK,
    SOFT_DEADLINE_S,
    _chunk_count,
    _prune_jobs_locked,
    _shim_spill_dir,
    _spawn_job,
    _stash_result,
    _write_listing_spill,
)
from .listing import (
    BACKEND_TOOL_META,
    _flat_text_from_content,
    _log_tail,
    _result_text,
    server,
)
from .sessions import (
    SESSIONS,
    _close,
    _ensure_backend,
    _list,
    _open,
    _resolve,
)
from .transforms import (
    _apply_response_transforms,
    _coerce_none_string_fields,
    _pop_transformer_args,
)


def _inject_binary_name(name: str, args: dict, st: dict) -> None:
    """Inject ``binary_name=<program>`` into ``args`` for backend tools
    that multiplex on it. Caller-supplied binary_name wins; tools whose
    schema doesn't declare it (project-level verbs, when schemas are
    cached) get nothing extra."""
    if "binary_name" in args:
        return
    meta = BACKEND_TOOL_META.get(name)
    if meta is not None:
        props = (meta.get("inputSchema") or {}).get("properties") or {}
        if "binary_name" not in props:
            return
    args["binary_name"] = st["program"]


async def _fetch_nearest_function(sess, st, address) -> dict | None:
    """Best-effort ``nearest_function`` blob for ``address``.

    Calls the extension's ``ghidra_query_context`` under the session
    lock, then computes the {start, end, delta, name} enrichment via
    the pure helper. Every failure mode returns None — no cascading
    errors on top of an already-broken decompile call.
    """
    if address is None:
        return None
    ea_str = hex(address) if isinstance(address, int) else str(address)
    ctx: dict | None = None
    try:
        async with st["lock"]:
            r = await sess.call_tool(
                "ghidra_query_context",
                {"binary_name": st["program"], "address": ea_str})
    except Exception:  # noqa: BLE001 - enrichment is best-effort
        return None
    if r.isError:
        return None
    text = _flat_text_from_content(r.content) or ""
    if not text or text[0] not in "[{":
        return None
    try:
        ctx = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(ctx, dict):
        return None
    # ghidra_query_context already returns function_name — carry it
    # straight through.
    fn_name = ctx.get("function_name") if ctx.get("in_function") else None
    return _compute_nearest_function(ctx, ea_str, fn_name)


async def _try_decompile_disasm_fallback(
    sess, st, args: dict, err_result,
) -> list | None:
    """When `decompile_function` fails (mid-function address, analysis
    not done) auto-retry with `disassemble_function` at the same
    address. On either path attach ``nearest_function`` computed from
    ``ghidra_query_context``.
    """
    address = (args.get("name_or_address") or args.get("start_address")
               or args.get("address") or args.get("ea")
               or args.get("func"))
    if address is None:
        return None
    # A pure function NAME can't drive a disasm fallback meaningfully —
    # names resolve or they don't; bail to the plain error.
    if isinstance(address, str) and not address.strip().lower().startswith("0x") \
            and not address.strip().isdigit():
        return None

    nearest = await _fetch_nearest_function(sess, st, address)

    try:
        async with st["lock"]:
            r = await sess.call_tool(
                "disassemble_function",
                {"binary_name": st["program"], "address": address})
    except Exception:  # noqa: BLE001
        envelope = {
            "ok": False,
            "kind": "decompile_failed",
            "status": "decompile_failed",
            "address": (hex(address) if isinstance(address, int)
                        else str(address)),
            "decompile_error": _result_text(err_result),
            "nearest_function": nearest,
            "hint": ("no function at this address; try "
                     "ghidra_manage(action='create_function', "
                     "args_json='{\"address\":...}') or "
                     "resolve_offset if you meant a struct member"),
        }
        return [types.TextContent(type="text",
                                  text=json.dumps(envelope, indent=2))]
    if r.isError:
        envelope = {
            "ok": False,
            "kind": "decompile_failed",
            "status": "decompile_failed",
            "address": (hex(address) if isinstance(address, int)
                        else str(address)),
            "decompile_error": _result_text(err_result),
            "disasm_error": _result_text(r),
            "nearest_function": nearest,
            "hint": ("no function at this address; try "
                     "ghidra_manage(action='create_function', "
                     "args_json='{\"address\":...}') or "
                     "resolve_offset if you meant a struct member"),
        }
        return [types.TextContent(type="text",
                                  text=json.dumps(envelope, indent=2))]

    disasm_text = _flat_text_from_content(r.content) or ""
    envelope = {
        "status": "fallback_disasm",
        "address": (hex(address) if isinstance(address, int) else str(address)),
        "decompile_error": _result_text(err_result),
        "disassembly": disasm_text,
        "nearest_function": nearest,
        "hint": "Ghidra could not decompile this address (mid-function, "
                "corrupted analysis, or analysis still running); the "
                "fallback disassembly above is the best we can do — for "
                "the correct function head, try "
                "ghidra_manage(action='create_function', "
                "args_json='{\"address\":...}')",
    }
    return [types.TextContent(type="text", text=json.dumps(envelope, indent=2))]


# ------------------------------------- ghidra_job_* shim tools ----


async def _ghidra_job_start(tool: str = "", args_json: str = "{}",
                            database: str = "", **_kw) -> str:
    """Explicit background job. Prefer letting _call_tool auto-promote —
    this is for cases where you know up-front the call will be slow."""
    if not tool:
        raise RuntimeError("ghidra_job_start: 'tool' is required")
    if tool in ("ghidra_open", "ghidra_list", "ghidra_close", "ghidra_log",
                "ghidra_job_start", "ghidra_job_status", "ghidra_result",
                "ghidra_job_cancel", "ghidra_job_list"):
        raise RuntimeError(
            f"ghidra_job_start: refusing to background management tool {tool!r}")
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ghidra_job_start: args_json parse error: {exc}") from None
    db_key = database or args.pop("database", None)
    await _ensure_backend()
    sid, sess = _resolve(db_key)
    st = SESSIONS[sid]
    _inject_binary_name(tool, args, st)

    async def _do() -> list:
        async with st["lock"]:
            r = await sess.call_tool(tool, args)
        if r.isError:
            raise RuntimeError(_result_text(r))
        return r.content

    job_id = await _spawn_job(tool, args, sid, _do)
    return json.dumps({"job_id": job_id, "status": "pending", "tool": tool})


async def _ghidra_job_status(job_id: str = "", **_kw) -> str:
    if not job_id:
        raise RuntimeError("ghidra_job_status: 'job_id' is required")
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ghidra_job_status: unknown job {job_id!r}")
        elapsed = ((j.get("finished_at") or time.monotonic()) - j["started_at"])
        out = {
            "job_id": job_id,
            "tool": j["tool"],
            "status": j["status"],
            "elapsed_s": round(elapsed, 3),
            "total_bytes": j["total_bytes"],
            "total_chunks": _chunk_count(j["total_bytes"], j["chunk_bytes"]),
            "chunk_bytes": j["chunk_bytes"],
        }
        if j["status"] == "error":
            out["error"] = j["error"]
    return json.dumps(out)


async def _ghidra_result(job_id: str = "", page: int = 0,
                         page_size: int = 0, sha256: str = "",
                         **_kw) -> str:
    """Return one chunk of a completed job's result_text.

    Accepts either the legacy in-memory `job_id` or a content-addressed
    `sha256` — or a raw 64-hex `job_id`, treated as the sha256. With
    sha256 the listing bytes are read from the shim's spill dir so the
    payload remains fetchable after the JOBS retention window.
    """
    key = sha256 or job_id
    if key and len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
        path = _shim_spill_dir() / f"{key.lower()}.listing"
        if not path.exists():
            raise RuntimeError(
                f"ghidra_result: no spilled listing for sha256 {key[:12]}...")
        raw = path.read_bytes()
        MAX_PAGE = 128 * 1024
        if page_size >= 1024:
            chunk_bytes = min(page_size, MAX_PAGE)
        else:
            chunk_bytes = CHUNK_BYTES
        total_pages = _chunk_count(len(raw), chunk_bytes)
        if total_pages == 0:
            chunk = b""
        else:
            if page < 0 or page >= total_pages:
                raise RuntimeError(
                    f"ghidra_result: page {page} out of range (total={total_pages})")
            start = page * chunk_bytes
            chunk = raw[start:start + chunk_bytes]
        return json.dumps({
            "sha256": key.lower(), "status": "done",
            "page": page, "total_pages": total_pages,
            "chunk_bytes": chunk_bytes,
            "is_last": (page + 1) >= total_pages,
            "data": chunk.decode("utf-8", errors="replace"),
        })
    if not job_id:
        raise RuntimeError("ghidra_result: 'job_id' or 'sha256' is required")
    if page < 0:
        raise RuntimeError("ghidra_result: page must be >= 0")
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ghidra_result: unknown job {job_id!r}")
        if j["status"] == "pending":
            return json.dumps({
                "job_id": job_id, "status": "pending",
                "hint": "not ready yet; poll ghidra_job_status.",
            })
        if j["status"] == "error":
            return json.dumps({"job_id": job_id, "status": "error",
                               "error": j["error"]})
        if j["status"] == "cancelled":
            return json.dumps({"job_id": job_id, "status": "cancelled"})
        text = j["result_text"] or ""
        chunk_bytes = page_size if page_size > 0 else j["chunk_bytes"]
        MAX_PAGE = 128 * 1024
        if chunk_bytes > MAX_PAGE:
            chunk_bytes = MAX_PAGE
        total_pages = _chunk_count(len(text), chunk_bytes)
        if total_pages == 0:
            data = ""
        else:
            if page >= total_pages:
                raise RuntimeError(
                    f"ghidra_result: page {page} out of range (total={total_pages})")
            start = page * chunk_bytes
            data = text[start:start + chunk_bytes]
    return json.dumps({
        "job_id": job_id, "status": "done",
        "page": page, "total_pages": total_pages,
        "chunk_bytes": chunk_bytes,
        "is_last": (page + 1) >= total_pages,
        "data": data,
    })


async def _ghidra_job_cancel(job_id: str = "", **_kw) -> str:
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ghidra_job_cancel: unknown job {job_id!r}")
        was = j["status"] == "pending"
        task = j.get("task")
    if was and task is not None:
        task.cancel()
    return json.dumps({"job_id": job_id, "cancelled": was})


async def _ghidra_job_list(active_only: bool = False, **_kw) -> str:
    async with JOBS_LOCK:
        await _prune_jobs_locked()
        out = []
        for jid, j in JOBS.items():
            if active_only and j["status"] != "pending":
                continue
            elapsed = ((j.get("finished_at") or time.monotonic()) - j["started_at"])
            out.append({
                "job_id": jid, "tool": j["tool"], "status": j["status"],
                "elapsed_s": round(elapsed, 3), "total_bytes": j["total_bytes"],
            })
    return json.dumps({"count": len(out), "jobs": out})


async def _call_passthrough(name: str, arguments: dict) -> list[types.Content]:
    """Non-management tool passthrough with soft-timeout auto-promotion
    and oversized-result auto-chunking."""
    args = dict(arguments)
    database = args.pop("database", None)
    # Respawn the shared backend on demand — a JVM crash drops every
    # session's transport, but SESSIONS survives and the next call
    # transparently reconnects.
    await _ensure_backend()
    sid, sess = _resolve(database)
    st = SESSIONS[sid]

    # Rewrite alias arg names to canonical forms before the backend sees
    # them (start_address -> name_or_address on decompile, code/script ->
    # source on exec_ghidra_script, struct/member on get_struct_member).
    args = _apply_arg_aliases(name, args)

    # Pull client-side transformer knobs off `args` BEFORE the backend
    # sees them.
    transformer_args = _pop_transformer_args(name, args)

    # Shared-backend multiplexing: the program this session owns.
    _inject_binary_name(name, args, st)

    async def _do() -> list:
        async with st["lock"]:
            r = await sess.call_tool(name, args)
        if r.isError:
            # decompile_function mid-function / no-decompile errors
            # auto-retry with disassemble_function at the same address.
            if name == "decompile_function":
                fallback = await _try_decompile_disasm_fallback(sess, st, args, r)
                if fallback is not None:
                    return fallback
            raise RuntimeError(_result_text(r))
        _coerce_none_string_fields(name, sess, r)
        content = _apply_response_transforms(name, args, transformer_args,
                                             r.content)
        return content

    # Shield so a caller-side cancellation doesn't tear down the tool
    # call mid-flight; the result stays retrievable via ghidra_result.
    task = asyncio.create_task(_do(), name=f"ghidra-tool-{name}")
    try:
        content = await asyncio.wait_for(asyncio.shield(task),
                                          timeout=SOFT_DEADLINE_S)
    except asyncio.TimeoutError:
        job_id = "j_" + uuid.uuid4().hex[:12]

        async def _watchdog() -> None:
            try:
                res = await task
                txt = _flat_text_from_content(res)
                sha_out: str | None = None
                if len(txt) > CHUNK_BYTES:
                    sha_out = _write_listing_spill(
                        txt.encode("utf-8", errors="replace"))
                async with JOBS_LOCK:
                    j = JOBS.get(job_id)
                    if j is not None:
                        j["status"] = "done"
                        j["result_text"] = txt
                        j["total_bytes"] = len(txt)
                        j["finished_at"] = time.monotonic()
                        if sha_out is not None:
                            j["sha256"] = sha_out
            except Exception as exc:  # noqa: BLE001
                async with JOBS_LOCK:
                    j = JOBS.get(job_id)
                    if j is not None:
                        j["status"] = "error"
                        j["error"] = f"{type(exc).__name__}: {exc}"
                        j["finished_at"] = time.monotonic()

        asyncio.create_task(_watchdog(), name=f"ghidra-watchdog-{job_id}")
        started_at = time.monotonic() - SOFT_DEADLINE_S
        async with JOBS_LOCK:
            await _prune_jobs_locked()
            JOBS[job_id] = {
                "tool": name, "args": args, "sid": sid,
                "task": task, "started_at": started_at,
                "status": "pending", "result_text": None,
                "error": None, "total_bytes": 0,
                "chunk_bytes": CHUNK_BYTES,
                "finished_at": None,
                "sha256": None,
            }
        return [types.TextContent(
            type="text",
            text=_pending_envelope(
                job_id, name, action=name,
                elapsed_ms=int(SOFT_DEADLINE_S * 1000),
            ),
        )]

    text = _flat_text_from_content(content)
    if len(text) > CHUNK_BYTES:
        job_id = await _stash_result(name, args, sid, text)
        env_text = _chunked_envelope(job_id, name, text, action=name)
        try:
            sha = json.loads(env_text)["artifact"]["sha256"]
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is not None:
                    j["sha256"] = sha
        except (KeyError, ValueError):
            pass
        return [types.TextContent(type="text", text=env_text)]
    return content


@server.call_tool()
async def _call_tool(name: str, arguments: dict) -> list[types.Content]:
    if name == "ghidra_open":
        # Shield: if the bridge times out waiting for us, we still finish
        # spawning + registering the backend session in SESSIONS. A
        # subsequent call sees it in BY_PATH and short-circuits.
        text = await asyncio.shield(asyncio.ensure_future(_open(**arguments)))
    elif name == "ghidra_list":
        text = await _list()
    elif name == "ghidra_close":
        text = await _close(**arguments)
    elif name == "ghidra_log":
        text = await _log_tail(**arguments)
    elif name == "ghidra_job_start":
        text = await _ghidra_job_start(**arguments)
    elif name == "ghidra_job_status":
        text = await _ghidra_job_status(**arguments)
    elif name == "ghidra_result":
        text = await _ghidra_result(**arguments)
    elif name == "ghidra_job_cancel":
        text = await _ghidra_job_cancel(**arguments)
    elif name == "ghidra_job_list":
        text = await _ghidra_job_list(**arguments)
    else:
        return await _call_passthrough(name, arguments)
    return [types.TextContent(type="text", text=text)]
