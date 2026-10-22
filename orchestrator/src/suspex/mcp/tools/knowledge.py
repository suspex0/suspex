"""Knowledge tool registration for the suspex0 MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)
# Part 3 evidence envelope: retained-record read/prune surface.
from ..evidence import store as _ev_store
from ..evidence import views as _ev_views


def _ev_int(v: Any) -> int:
    """Defensive offset/limit coercion (accepts '0x...' strings)."""
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return 0


def _missing_evidence(evidence_id: str) -> str:
    """Standard ``missing_evidence`` error — malformed AND unknown ids both
    land here (never a filesystem path), with the exact id echoed."""
    return _j({
        "ok": False,
        "kind": "missing_evidence",
        "error": f"no evidence record {evidence_id!r}",
        "hint": ("records live for this orchestrator session; re-run the "
                 "producing action to recreate"),
    })


# v0.22: module-level so the lazy action-annotation resolves.
KNOWLEDGE_ACTIONS = [
    "record", "list", "update", "add_evidence", "sessions",
    # v0.18 shared knowledge base
    "about", "search", "annotate", "link", "mark_stale", "artifacts",
    # v0.20: the removed_action hint for generate_report pointed here
    # before it existed — now it does (full-KB JSON dump to reports/).
    "export_json",
    # Part 3 evidence envelope: page back / inspect / list / prune the
    # retained heavy-result records (see mcp/evidence/).
    "evidence_get", "evidence_summary", "evidence_list", "evidence_prune",
    # v0.22 discoverability
    "actions",
]


def register(mcp, ctx: Context) -> None:
    """Register the ``knowledge_manage`` tool on *mcp*, using *ctx* for state."""
    # --------------------------------------------------------- knowledge_manage --
    # v0.18: renamed from `findings_manage` to reflect the wider surface
    # (findings + notes + artifact index + tool-event breadcrumbs + IDA
    # sessions + FTS search). `findings_manage` is preserved as a
    # deprecation alias below.

    _KB_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "knowledge_manage(action='actions')"},
        "record": {"one_liner": "file a finding (dedupes on "
                                "title/artifact_sha/address)",
                   "key_args": "title, description, severity, artifact_sha, "
                               "address, dedupe",
                   "example": "knowledge_manage(action='record', "
                              "title='pool tag X is owned by Y.sys', "
                              "artifact_sha='...')"},
        "list": {"one_liner": "list findings (filter by session/severity)",
                 "key_args": "session_id, severity, limit/offset",
                 "example": "knowledge_manage(action='list')"},
        "update": {"one_liner": "change a finding's status/severity/title",
                   "key_args": "finding_id, status, severity, title",
                   "example": "knowledge_manage(action='update', "
                              "finding_id='f-123', status='confirmed')"},
        "add_evidence": {"one_liner": "attach evidence to an existing "
                                      "finding",
                         "key_args": "finding_id, evidence_kind, content",
                         "example": "knowledge_manage(action='add_evidence', "
                                    "finding_id='f-123', content='...')"},
        "sessions": {"one_liner": "list KB sessions",
                     "key_args": "none",
                     "example": "knowledge_manage(action='sessions')"},
        "about": {"one_liner": "check-first lookup: findings + notes + "
                               "events for an artifact/module/address/target",
                  "key_args": "artifact_sha | alias | module | address | target",
                  "example": "knowledge_manage(action='about', "
                             "alias='nvlddmkm.sys')"},
        "search": {"one_liner": "FTS over findings + notes + evidence",
                   "key_args": "q, search_kind, limit",
                   "example": "knowledge_manage(action='search', "
                              "q='object header')"},
        "annotate": {"one_liner": "write a scratch note (no finding "
                                  "ceremony)",
                     "key_args": "content, note_kind, artifact_sha/module/address",
                     "example": "knowledge_manage(action='annotate', "
                                "content='tmp note', module='X.sys')"},
        "link": {"one_liner": "link a finding to another artifact/session",
                 "key_args": "finding_id, artifact_sha/module/address",
                 "example": "knowledge_manage(action='link', "
                            "finding_id='f-123', artifact_sha='...')"},
        "mark_stale": {"one_liner": "flag a finding as stale with a reason",
                       "key_args": "finding_id, stale_reason",
                       "example": "knowledge_manage(action='mark_stale', "
                                  "finding_id='f-123', stale_reason='rebased')"},
        "artifacts": {"one_liner": "version index — every sha256 under an "
                                   "alias",
                      "key_args": "alias | module",
                      "example": "knowledge_manage(action='artifacts', "
                                 "alias='ntoskrnl.exe')"},
        "export_json": {"one_liner": "dump the whole KB to reports/ as JSON",
                        "key_args": "out_dir",
                        "example": "knowledge_manage(action='export_json')"},
        "evidence_get": {"one_liner": "page a retained heavy-result record "
                                      "back by evidence_id",
                         "key_args": "evidence_id, offset, limit",
                         "example": "knowledge_manage(action='evidence_get', "
                                    "evidence_id='ev_...', offset=0, "
                                    "limit=64)"},
        "evidence_summary": {"one_liner": "counts + provenance + coverage "
                                          "for a retained record (no "
                                          "payload)",
                             "key_args": "evidence_id",
                             "example": "knowledge_manage("
                                        "action='evidence_summary', "
                                        "evidence_id='ev_...')"},
        "evidence_list": {"one_liner": "list retained evidence records "
                                       "(metadata only, paged)",
                          "key_args": "filter, offset, limit",
                          "example": "knowledge_manage(action='evidence_list', "
                                     "limit=50)"},
        "evidence_prune": {"one_liner": "delete one retained record (or all "
                                        "with evidence_id='' + confirm=true; "
                                        "needs allow_delete)",
                           "key_args": "evidence_id, confirm",
                           "example": "knowledge_manage(action='evidence_prune', "
                                      "evidence_id='ev_...')"},
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def knowledge_manage(action: Annotated[str, Field(json_schema_extra={"enum": KNOWLEDGE_ACTIONS})],
                               session_id: str = "", severity: str = "info",
                              title: str = "", description: str = "", refs: str = "",
                              finding_id: str = "", status: str = "", evidence_kind: str = "note",
                              content: str = "", out_dir: str = "",
                              # v0.18 shared-knowledge scoping fields
                              artifact_sha: str = "", module: str = "",
                              address: str = "", function: str = "",
                              alias: str = "", target: str = "",
                              supersedes: str = "", dedupe: bool = True,
                              note_kind: str = "context",
                              # v0.24: artifacts-relative path scoping for about()
                              path: str = "",
                              q: str = "", since: str = "", agent: str = "",
                              search_kind: str = "", kind: str = "",
                              stale_reason: str = "",
                              # v0.14 unified paging (Layer 3)
                              limit: int = 0,
                              offset: int = 0,
                              max_results: int = 0,
                              cursor: str = "",
                              verbosity: str = "normal",
                              fields: list[str] | None = None,
                              filter: Any = "",
                              summary: bool = False,
                              evidence_id: str = "",
                              confirm: bool = False) -> str:
        """Shared knowledge base: findings, notes, artifact index, tool
        breadcrumbs. Renamed from ``findings_manage`` in v0.18 (the old
        name still works). Per-verb help:
        knowledge_manage(action='actions')."""
        args = {"action": action, "finding_id": finding_id,
                "artifact_sha": artifact_sha, "module": module,
                "address": address, "alias": alias,
                # Forward verbosity so _guard's _opts_from_args honors it in
                # finalize (list/search row-collapse opt-out via full/raw).
                "verbosity": verbosity}

        async def run() -> str:
            led = ctx.ledger
            cid = current_client_id()
            if action == "record":
                sid = session_id or ctx.get_current_session_id(cid) or led.start_session(
                    ctx.session.cfg.target_endpoint)
                if not ctx.get_current_session_id(cid):
                    ctx.set_current_session_id(cid, sid)
                fid, dup = led.record_ex(
                    sid, severity, title, description, refs,
                    agent_id=cid, artifact_sha=artifact_sha, module=module,
                    address=address, function=function, supersedes=supersedes,
                    dedupe=bool(dedupe),
                )
                out = {"ok": True, "finding_id": fid, "session_id": sid}
                if dup:
                    out["duplicate_of"] = dup
                    out["hint"] = (
                        "an open finding with the same title+sha+address already"
                        " exists; add_evidence to append, or dedupe=false to force"
                        " a new row"
                    )
                return _j(out)
            if action == "list":
                # v0.18: default scope is now GLOBAL (all sessions). Pass
                # session_id explicitly to filter — nothing else changed.
                rows = [f.__dict__ for f in led.list_findings(
                    session_id or None, status or None)]
                eff_limit = limit or max_results
                return _j(_list_envelope(
                    rows, tool="knowledge_manage", action="list",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ))
            if action == "update":
                led.update(finding_id, status or None, title or None,
                           description or None, severity or None)
                return _j({"ok": True})
            if action == "add_evidence":
                eid = led.add_evidence(finding_id, evidence_kind, content)
                return _j({"ok": True, "evidence_id": eid})
            if action == "sessions":
                return _j(led.sessions())
            if action == "about":
                # v0.24: path= (artifacts-relative or absolute) resolves to
                # the artifact sha so "what do we know about this dump" works
                # straight after dump_module — no manual sha threading.
                eff_sha = artifact_sha
                path_note = ""
                if path and not eff_sha:
                    from pathlib import Path as _P
                    from .._artifacts import resolve_artifact_path as _rap
                    cand = _P(path).expanduser()
                    if not cand.is_file():
                        # Canonical store resolution covers 'dumps/x.sys',
                        # 'artifacts/dumps/x.sys', and abs-under-root.
                        rp = _rap(ctx.cfg, path)
                        if rp is not None and rp.is_file():
                            cand = rp
                        else:
                            alt = _P(ctx.cfg.artifacts_dir()) / path
                            cand = alt if alt.is_file() else cand
                    if cand.is_file():
                        digest, _sz = _sha256_file(str(cand))
                        if digest:
                            eff_sha = digest
                            path_note = str(cand)
                    if not eff_sha:
                        return _j({"ok": False, "kind": "not_found",
                                   "error": f"about(path={path!r}): no local "
                                            "file at that path (absolute or "
                                            "artifacts-relative)"})
                if not any([eff_sha, alias, module, address, function,
                            target]):
                    return _j({
                        "ok": False,
                        "kind": "bad_arg",
                        "error": ("about() requires at least one scoping key:"
                                  " artifact_sha, alias, module, address,"
                                  " function, target or path"),
                    })
                eff_limit = limit or max_results or 50
                try:
                    result = led.about(
                        sha=eff_sha, alias=alias, module=module,
                        address=address, function=function, target=target,
                        limit=eff_limit,
                    )
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
                if path_note:
                    result["resolved_path"] = path_note
                return _j({"ok": True, **result})
            if action == "search":
                if not q:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "search() requires q"})
                since_v: float | None = None
                if since:
                    try:
                        since_v = float(since)
                    except ValueError:
                        try:
                            import datetime as _dt
                            since_v = _dt.datetime.fromisoformat(since).timestamp()
                        except (ValueError, TypeError):
                            return _j({"ok": False, "kind": "bad_arg",
                                       "error": f"unparseable since: {since!r}"})
                eff_limit = limit or max_results or 50
                hits = led.search(q, since=since_v, agent=agent,
                                  kind=search_kind, limit=eff_limit)
                return _j({"ok": True, "hits": hits, "count": len(hits)})
            if action == "annotate":
                if not content:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "annotate() requires content"})
                nid = led.annotate(
                    content, agent_id=cid, artifact_sha=artifact_sha,
                    module=module, address=address, function=function,
                    target=target, kind=note_kind or "context",
                )
                return _j({"ok": True, "note_id": nid})
            if action == "link":
                if not finding_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "link() requires finding_id"})
                ok = led.link(
                    finding_id,
                    artifact_sha=artifact_sha or None,
                    module=module or None,
                    address=address or None,
                    function=function or None,
                )
                if not ok:
                    return _j({"ok": False, "kind": "not_found",
                               "error": f"no finding with id {finding_id!r}"})
                return _j({"ok": True, "finding_id": finding_id})
            if action == "mark_stale":
                if not any([finding_id, module, target]):
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": ("mark_stale requires finding_id OR"
                                         " module OR target")})
                n = led.mark_stale(
                    finding_id=finding_id or None,
                    filter_module=(module or None) if not finding_id else None,
                    filter_target=(target or None) if not finding_id else None,
                    reason=stale_reason,
                )
                return _j({"ok": True, "marked": n})
            if action == "artifacts":
                eff_limit = limit or max_results or 100
                rows = [a.__dict__ for a in led.artifacts_list(
                    alias=alias, sha=artifact_sha, kind=kind, limit=eff_limit)]
                for r in rows:
                    r["findings_count"] = led._count(
                        "findings", "artifact_sha=?", (r["sha256"],))
                    r["notes_count"] = led._count(
                        "notes", "artifact_sha=?", (r["sha256"],))
                    r["events_count"] = led._count(
                        "tool_events", "artifact_sha=?", (r["sha256"],))
                return _j({"ok": True, "artifacts": rows, "count": len(rows)})
            if action == "generate_report":
                # v0.18: dropped. Kept an explicit steer for anyone with
                # scripted callers so they see the migration hint instead
                # of a generic unknown_action.
                return _j({
                    "ok": False,
                    "kind": "removed_action",
                    "error": ("generate_report was removed in v0.18. Use"
                              " knowledge_manage(action='export_json' |"
                              " 'list' | 'about') or read the SQLite DB"
                              " directly."),
                })
            if action == "export_json":
                # v0.20: the removed_action hint above used to name this
                # action before it existed — implement it rather than
                # reword the hint. Full findings+evidence JSON dumped to
                # reports_dir; oversized content spills per convention.
                import datetime as _dt
                import json as _json
                findings = ctx.ledger.list_findings()
                payload = _json.loads(ctx.ledger.export_json())
                out_dir = ctx.cfg.reports_dir()
                out_dir.mkdir(parents=True, exist_ok=True)
                stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                p = out_dir / f"knowledge_export_{stamp}.json"
                p.write_text(_json.dumps(payload, indent=2),
                             encoding="utf-8")
                return _j({"ok": True, "path": str(p),
                           "findings": len(payload),
                           "bytes": p.stat().st_size})
            if action in ("evidence_get", "evidence_summary"):
                # Recorded target content renders back out here — callers
                # must treat it as data, never instructions (Part 1
                # classifies these UNTRUSTED_SESSION).
                root = Path(ctx.cfg.artifacts_dir())
                try:
                    rec = _ev_store.load(evidence_id, artifacts_root=root)
                except (_ev_store.EvidenceIdError, FileNotFoundError):
                    return _missing_evidence(evidence_id)
                if action == "evidence_get":
                    off = max(0, _ev_int(offset))
                    lim = _ev_int(limit) or 64
                    lim = max(1, min(lim, 4096))
                    page, total, truncated = _ev_views.page_view(
                        rec, offset=off, limit=lim)
                    page_len = len(page) if isinstance(page, (str, list)) else 1
                    return _j(_envelope_ok(
                        {"evidence_id": evidence_id,
                         "field": _ev_views.main_field(rec),
                         "offset": off, "content": page},
                        kind=_resolve_kind("knowledge_manage", "evidence_get"),
                        tool="knowledge_manage", action="evidence_get",
                        item_count=page_len, item_total=total,
                        truncated=True if truncated else None,
                        next_cursor=(f"offset:{off + page_len}"
                                     if truncated else None),
                    ))
                out = _ev_views.summary_view(rec)
                row = ctx.ledger.evidence_record(evidence_id)
                if row:
                    for k in ("created", "tool", "action", "detail",
                              "size_bytes"):
                        if row.get(k) is not None:
                            out[k] = row[k]
                return _j({"ok": True, **out})
            if action == "evidence_list":
                rows = ctx.ledger.evidence_records()
                return _j(_list_envelope(
                    rows, tool="knowledge_manage", action="evidence_list",
                    limit=limit or max_results or 50, offset=offset,
                    filter=filter,
                    global_cap=ctx.cfg.mcp_max_items(),
                ))
            if action == "evidence_prune":
                # Gated in Session.assert_allowed via security.allow_delete;
                # the no-id bulk form additionally demands confirm=true.
                root = Path(ctx.cfg.artifacts_dir())
                if evidence_id:
                    try:
                        gone = _ev_store.delete(evidence_id, artifacts_root=root)
                    except _ev_store.EvidenceIdError:
                        return _missing_evidence(evidence_id)
                    removed = bool(ctx.ledger.delete_evidence_record(evidence_id)) or gone
                    return _j({"ok": True, "deleted": 1 if removed else 0})
                if not confirm:
                    return _j({
                        "ok": False,
                        "kind": "bad_arg",
                        "error": ("evidence_prune with no evidence_id deletes"
                                  " ALL retained evidence records; pass"
                                  " confirm=true to proceed"),
                    })
                n_rows = ctx.ledger.delete_all_evidence_records()
                n_files = _ev_store.delete_all(root)
                return _j({"ok": True, "deleted": max(n_rows, n_files),
                           "rows": n_rows, "files": n_files})
            if action == "actions":
                return _actions_help("knowledge_manage", _KB_ACTION_HELP)
            return _unknown_action("knowledge_manage", action, KNOWLEDGE_ACTIONS, _KB_ACTION_HELP)

        return await _guard(ctx, "knowledge_manage", action, args, run)

    # v0.18 deprecation alias: legacy `findings_manage` name. Delegates
    # to knowledge_manage so a Kilo/Devin session that hasn't refreshed
    # its skill doc still works. Slated for removal in v0.19+.
    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def findings_manage(action: Annotated[str, Field(json_schema_extra={"enum": KNOWLEDGE_ACTIONS})],
                              session_id: str = "", severity: str = "info",
                              title: str = "", description: str = "", refs: str = "",
                              finding_id: str = "", status: str = "", evidence_kind: str = "note",
                              content: str = "", out_dir: str = "",
                              artifact_sha: str = "", module: str = "",
                              address: str = "", function: str = "",
                              alias: str = "", target: str = "",
                              supersedes: str = "", dedupe: bool = True,
                              note_kind: str = "context",
                              q: str = "", since: str = "", agent: str = "",
                              search_kind: str = "", kind: str = "",
                              stale_reason: str = "",
                              limit: int = 0, offset: int = 0,
                              max_results: int = 0, cursor: str = "",
                              verbosity: str = "normal",
                              fields: list[str] | None = None,
                              filter: Any = "",
                              summary: bool = False,
                              evidence_id: str = "",
                              confirm: bool = False) -> str:
        """DEPRECATED (v0.18): use ``knowledge_manage`` instead. This
        alias forwards every call unchanged and will be removed in a
        future release."""
        log.warning("findings_manage is deprecated in v0.18; use "
                    "knowledge_manage. Forwarding action=%r.", action)
        res = await knowledge_manage(
            action, session_id=session_id, severity=severity, title=title,
            description=description, refs=refs, finding_id=finding_id,
            status=status, evidence_kind=evidence_kind, content=content,
            out_dir=out_dir, artifact_sha=artifact_sha, module=module,
            address=address, function=function, alias=alias, target=target,
            supersedes=supersedes, dedupe=dedupe, note_kind=note_kind,
            q=q, since=since, agent=agent, search_kind=search_kind, kind=kind,
            stale_reason=stale_reason, limit=limit, offset=offset,
            max_results=max_results, cursor=cursor, verbosity=verbosity,
            fields=fields, filter=filter, summary=summary,
            evidence_id=evidence_id, confirm=confirm,
        )
        # v0.28: the server-side log line above never reaches the MCP
        # client — stamp the deprecation into the response body so
        # sessions visibly learn the new name instead of silently
        # living on the alias.
        dep = ("findings_manage is DEPRECATED (v0.18) — call "
               "knowledge_manage instead; the alias will be removed")
        from .common import _j as _jj
        from .._envelope import warn as _warn
        body = getattr(res, "structured_content", None)
        if isinstance(body, dict):
            return _jj(_warn(dict(body), dep))
        if isinstance(res, str):
            import json as _json
            try:
                parsed = _json.loads(res)
                if isinstance(parsed, dict):
                    return _jj(_warn(parsed, dep))
            except (ValueError, TypeError):
                pass
        return res
