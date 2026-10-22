"""Tool-call dispatch: passthrough with auto-promotion + oversized-result
auto-chunking, plus the ``ida_job_*`` / ``ida_result`` shim tools.

This is where the shim's ``@server.call_tool()`` handler and the
decompile-fallback / nearest-function enrichment live.

Mechanical split-out from ``idalib_stdio_shim.py``; no behavior changes.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid

import mcp.types as types

from ida_shim_ergo import (
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
    _flat_text_from_content,
    _log_tail,
    _result_text,
    server,
)
from .sessions import SESSIONS, _close, _list, _open, _resolve
from .transforms import (
    _apply_response_transforms,
    _coerce_none_string_fields,
    _pop_transformer_args,
)


async def _fetch_nearest_function(sess, st, address) -> dict | None:
    """Best-effort ``nearest_function`` blob for ``address`` (D-4).

    Calls the extension's ``ida_query_context`` under the session lock,
    then computes the {start, end, delta, name} enrichment via the pure
    helper in :mod:`ida_shim_ergo`. Every failure mode returns None so the
    caller can inline the fallback envelope regardless of whether the
    enrichment succeeded — no cascading errors on top of an already-broken
    decompile call.
    """
    if address is None:
        return None
    ea_str = hex(address) if isinstance(address, int) else str(address)
    ctx: dict | None = None
    try:
        async with st["lock"]:
            r = await sess.call_tool("ida_query_context", {"address": ea_str})
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
    # ``ida_query_context`` does NOT return function_name today; try one
    # more call to get it. Non-fatal if it fails — the caller still sees
    # {start, end, delta} without the name.
    fn_name: str | None = None
    if ctx.get("ok") and ctx.get("in_function") and ctx.get("function_start"):
        try:
            async with st["lock"]:
                nr = await sess.call_tool(
                    "get_function_by_address",
                    {"address": ctx["function_start"]},
                )
            if not nr.isError:
                fn_txt = _flat_text_from_content(nr.content) or ""
                if fn_txt and fn_txt[0] in "[{":
                    try:
                        fn = json.loads(fn_txt)
                        if isinstance(fn, dict):
                            fn_name = fn.get("name") or fn.get("function_name")
                    except (ValueError, TypeError):
                        pass
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            pass
    return _compute_nearest_function(ctx, ea_str, fn_name)


async def _try_decompile_disasm_fallback(
    sess, st, args: dict, err_result,
) -> list | None:
    """When `decompile_function` fails (mid-function address, no Hex-Rays,
    corrupted analysis) auto-retry with `disassemble_function` at the same
    address. v0.17 D-4: on either the fallback-disasm success path OR the
    fallback-also-fails path, attach ``nearest_function:{start, end,
    delta, name}`` computed from ``ida_query_context`` so the caller sees
    the containing function context in one round trip.

    Returns a synthesized content list with either a
    ``status:'fallback_disasm'`` (fallback disasm succeeded) or a
    ``ok:false, kind:'decompile_failed'`` (fallback also failed) envelope.
    Never returns None any more — the D-4 enrichment is always attached
    even when both decompile and fallback disasm bail.
    """
    address = args.get("start_address") or args.get("address") or args.get("ea")
    if address is None:
        return None

    # D-4: fire the nearest_function enrichment early so both branches
    # below carry it (a race between decompile-failed and the enrichment
    # call is harmless — ida_query_context is idempotent).
    nearest = await _fetch_nearest_function(sess, st, address)

    try:
        async with st["lock"]:
            r = await sess.call_tool("disassemble_function",
                                     {**args, "start_address": address})
    except Exception:  # noqa: BLE001
        # Both decompile and disasm bailed — synthesize a decompile_failed
        # envelope with the nearest_function context so the caller has
        # something actionable.
        envelope = {
            "ok": False,
            "kind": "decompile_failed",
            "status": "decompile_failed",
            "address": (hex(address) if isinstance(address, int)
                        else str(address)),
            "decompile_error": _result_text(err_result),
            "nearest_function": nearest,
            "hint": ("no function at this ea; try "
                     "ida_manage(action='create_function', "
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
            "hint": ("no function at this ea; try "
                     "ida_manage(action='create_function', "
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
        "hint": "Hex-Rays could not decompile this address (mid-function, "
                "corrupted analysis, or no Hex-Rays licence); the fallback "
                "disassembly above is the best we can do — for the correct "
                "function head, try ida_manage(action='create_function', "
                "args_json='{\"address\":...}')",
    }
    return [types.TextContent(type="text", text=json.dumps(envelope, indent=2))]


# ------------------------------------- ida_job_* shim tools ----


async def _ida_job_start(tool: str = "", args_json: str = "{}", database: str = "",
                         **_kw) -> str:
    """Explicit background job. Prefer letting _call_tool auto-promote —
    this is for cases where you know up-front the call will be slow."""
    if not tool:
        raise RuntimeError("ida_job_start: 'tool' is required")
    if tool in ("idb_open", "idb_list", "idb_close", "ida_log",
                "ida_job_start", "ida_job_status", "ida_result",
                "ida_job_cancel", "ida_job_list"):
        raise RuntimeError(
            f"ida_job_start: refusing to background management tool {tool!r}")
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ida_job_start: args_json parse error: {exc}") from None
    sid, sess = _resolve(database or args.pop("database", None))
    st = SESSIONS[sid]

    async def _do() -> list:
        async with st["lock"]:
            r = await sess.call_tool(tool, args)
        if r.isError:
            raise RuntimeError(_result_text(r))
        return r.content

    job_id = await _spawn_job(tool, args, sid, _do)
    return json.dumps({"job_id": job_id, "status": "pending", "tool": tool})


async def _ida_job_status(job_id: str = "", **_kw) -> str:
    if not job_id:
        raise RuntimeError("ida_job_status: 'job_id' is required")
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ida_job_status: unknown job {job_id!r}")
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


async def _ida_result(job_id: str = "", page: int = 0,
                      page_size: int = 0, sha256: str = "",
                      **_kw) -> str:
    """Return one chunk of a completed job's result_text.

    v0.14 backward compat: accepts either the legacy in-memory `job_id`
    (looked up in the JOBS cache) or a content-addressed `sha256` — or
    a raw 64-hex `job_id`, which is treated as the sha256. When sha256
    is used the listing bytes are read from the shim's spill dir so
    the payload remains fetchable after the JOBS retention window.
    """
    key = sha256 or job_id
    if key and len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
        path = _shim_spill_dir() / f"{key.lower()}.listing"
        if not path.exists():
            raise RuntimeError(
                f"ida_result: no spilled listing for sha256 {key[:12]}...")
        raw = path.read_bytes()
        # Match read_listing_page's chunk-size resolution EXACTLY so
        # both paths report the same total_pages / page for the same
        # artifact: callers pass either page_size>=1024 (honored) or a
        # smaller value that we substitute with CHUNK_BYTES.
        MAX_PAGE = 128 * 1024
        if page_size >= 1024:
            chunk_bytes = min(page_size, MAX_PAGE)
        else:
            chunk_bytes = CHUNK_BYTES
        # Slice raw BYTES (not decoded chars) so total_pages here lines
        # up with summary.item_total in _chunked_envelope, which is
        # computed over the encoded byte length.
        total_pages = _chunk_count(len(raw), chunk_bytes)
        if total_pages == 0:
            chunk = b""
        else:
            if page < 0 or page >= total_pages:
                raise RuntimeError(
                    f"ida_result: page {page} out of range (total={total_pages})")
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
        raise RuntimeError("ida_result: 'job_id' or 'sha256' is required")
    if page < 0:
        raise RuntimeError("ida_result: page must be >= 0")
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ida_result: unknown job {job_id!r}")
        if j["status"] == "pending":
            return json.dumps({
                "job_id": job_id, "status": "pending",
                "hint": "not ready yet; poll ida_job_status.",
            })
        if j["status"] == "error":
            return json.dumps({"job_id": job_id, "status": "error",
                               "error": j["error"]})
        if j["status"] == "cancelled":
            return json.dumps({"job_id": job_id, "status": "cancelled"})
        text = j["result_text"] or ""
        chunk_bytes = page_size if page_size > 0 else j["chunk_bytes"]
        # Enforce a per-page ceiling so we don't recreate the original
        # oversize-line failure. 128 KiB is comfortably under the 32 MiB
        # bridge limit but leaves room for the JSON envelope overhead.
        MAX_PAGE = 128 * 1024
        if chunk_bytes > MAX_PAGE:
            chunk_bytes = MAX_PAGE
        total_pages = _chunk_count(len(text), chunk_bytes)
        if total_pages == 0:
            data = ""
        else:
            if page >= total_pages:
                raise RuntimeError(
                    f"ida_result: page {page} out of range (total={total_pages})")
            start = page * chunk_bytes
            data = text[start:start + chunk_bytes]
    return json.dumps({
        "job_id": job_id, "status": "done",
        "page": page, "total_pages": total_pages,
        "chunk_bytes": chunk_bytes,
        "is_last": (page + 1) >= total_pages,
        "data": data,
    })


async def _ida_job_cancel(job_id: str = "", **_kw) -> str:
    async with JOBS_LOCK:
        j = JOBS.get(job_id)
        if j is None:
            raise RuntimeError(f"ida_job_cancel: unknown job {job_id!r}")
        was = j["status"] == "pending"
        task = j.get("task")
    if was and task is not None:
        task.cancel()
    return json.dumps({"job_id": job_id, "cancelled": was})


async def _ida_job_list(active_only: bool = False, **_kw) -> str:
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
    and oversized-result auto-chunking. Returns MCP content list; the
    contents may be a `__suspex_pending` or `__suspex_chunked` envelope
    when the direct sync return would fail the transport."""
    args = dict(arguments)
    database = args.pop("database", None)
    sid, sess = _resolve(database)
    st = SESSIONS[sid]

    # v0.16: rewrite alias arg names to their canonical forms before the
    # backend sees them so callers who use the neighbouring tool's arg
    # spelling get through without a round-trip.
    args = _apply_arg_aliases(name, args)

    # v0.17 D-1/D-2/D-3: pull the client-side transformer knobs off `args`
    # BEFORE the backend sees them (the vendored plugin's signature does
    # not know about them). Applied to the response after the call returns.
    transformer_args = _pop_transformer_args(name, args)

    async def _do() -> list:
        async with st["lock"]:
            r = await sess.call_tool(name, args)
        if r.isError:
            # v0.16: decompile_function mid-function / no-decompile errors
            # auto-retry with disassemble_function at the same address.
            if name == "decompile_function":
                fallback = await _try_decompile_disasm_fallback(sess, st, args, r)
                if fallback is not None:
                    return fallback
            raise RuntimeError(_result_text(r))
        # v0.16: coerce None -> "" on any outputSchema-declared string field
        # so anonymous IDA structs / stack-frame slots don't fail the mcp
        # SDK's output validator.
        _coerce_none_string_fields(name, sess, r)
        # v0.17 D-1/D-2/D-3: shape-reduce the response for tools whose
        # vanilla shape is duplicative or overly verbose. Idempotent no-op
        # for other tools; degrades gracefully when the payload isn't JSON.
        content = _apply_response_transforms(name, args, transformer_args,
                                             r.content)
        return content

    # Shield so a caller-side cancellation doesn't tear down the tool
    # call mid-flight; we can always retrieve the result via ida_result
    # once the job settles.
    task = asyncio.create_task(_do(), name=f"ida-tool-{name}")
    try:
        content = await asyncio.wait_for(asyncio.shield(task),
                                          timeout=SOFT_DEADLINE_S)
    except asyncio.TimeoutError:
        # Auto-promote to background job. The task keeps running under
        # its own reference; store it into JOBS with a wrapper that
        # updates the entry when it settles.
        job_id = "j_" + uuid.uuid4().hex[:12]

        async def _watchdog() -> None:
            try:
                res = await task
                txt = _flat_text_from_content(res)
                # v0.14 L6: auto-promoted jobs must also spill so
                # `file_manage(read_artifact, sha256=...)` can serve the
                # payload after the JOBS retention window expires.
                # Only bother when the result is over the chunk threshold
                # — small results stay in-memory only, matching the
                # legacy behavior for below-threshold sync results.
                sha_out: str | None = None
                if len(txt) > CHUNK_BYTES:
                    sha_out = _write_listing_spill(
                        txt.encode("utf-8", errors="replace")
                    )
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

        asyncio.create_task(_watchdog(), name=f"ida-watchdog-{job_id}")
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
        # _chunked_envelope hashes the same bytes it spills — pull the
        # sha256 back out of the envelope and record it on the JOBS entry
        # so legacy `ida_result(job_id=..., page=N)` fetches still line
        # up with the on-disk .listing artifact for the same payload.
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
    if name == "idb_open":
        # Shield: if the bridge times out waiting for us, we still finish
        # spawning + registering the backend session in SESSIONS. A
        # subsequent call sees it in BY_PATH and short-circuits.
        text = await asyncio.shield(asyncio.ensure_future(_open(**arguments)))
    elif name == "idb_list":
        text = await _list()
    elif name == "idb_close":
        text = await _close(**arguments)
    elif name == "ida_log":
        text = await _log_tail(**arguments)
    elif name == "ida_job_start":
        text = await _ida_job_start(**arguments)
    elif name == "ida_job_status":
        text = await _ida_job_status(**arguments)
    elif name == "ida_result":
        text = await _ida_result(**arguments)
    elif name == "ida_job_cancel":
        text = await _ida_job_cancel(**arguments)
    elif name == "ida_job_list":
        text = await _ida_job_list(**arguments)
    else:
        return await _call_passthrough(name, arguments)
    return [types.TextContent(type="text", text=text)]
