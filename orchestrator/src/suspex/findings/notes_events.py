"""Evidence, notes and tool-event breadcrumb mixin for ``FindingsLedger``.

Split from ``findings.py`` to keep individual modules under 600 lines.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid

from .models import Evidence, Note, ToolEvent, _now

log = logging.getLogger(__name__)


class NotesEventsMixin:
    """Mixin providing evidence, notes and tool-event methods on
    ``FindingsLedger``. Assumes the composite class also brings a
    ``self._conn`` sqlite3 connection (from :class:`LedgerCore`)."""

    def add_evidence(self, finding_id: str, kind: str, content: str) -> str:
        eid = uuid.uuid4().hex[:12]
        self._conn.execute(
            "INSERT INTO evidence (id, finding_id, kind, content, created)"
            " VALUES (?,?,?,?,?)",
            (eid, finding_id, kind, content, _now()),
        )
        self._conn.commit()
        return eid

    def evidence_for(self, finding_id: str) -> list[Evidence]:
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE finding_id=? ORDER BY created",
            (finding_id,),
        ).fetchall()
        return [Evidence(**dict(r)) for r in rows]

    # --------------------------------------------- evidence records (Part 3) ----
    # Unattached tool_result evidence rows backing the evidence envelope.
    # The row id IS the deterministic ev_ digest, so double retention
    # (tool stamp + spill path) collapses to one row via INSERT OR IGNORE.
    # add_evidence above keeps its finding-attached signature untouched.

    def add_evidence_record(self, digest: str, tool: str, action: str,
                            operation: str, coverage_json: str,
                            size_bytes: int, detail: str, parent_id: str,
                            content_preview: str) -> str:
        """Insert an unattached ``tool_result`` evidence row keyed by the
        deterministic digest; returns the digest. Errors are logged and
        swallowed — retention must never break the producing tool call."""
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO evidence"
                " (id, finding_id, kind, content, created, digest,"
                "  operation, tool, action, coverage_json, size_bytes,"
                "  detail, parent_id)"
                " VALUES (?, '', 'tool_result', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (digest, content_preview, _now(), digest, operation, tool,
                 action, coverage_json, int(size_bytes), detail, parent_id),
            )
            self._conn.commit()
            return digest
        except sqlite3.Error as exc:
            log.warning("add_evidence_record dropped (%s): %s", digest, exc)
            return ""

    def evidence_record(self, evidence_id: str) -> dict | None:
        """One tool_result evidence row (metadata only, no payload)."""
        row = self._conn.execute(
            "SELECT * FROM evidence WHERE id=? AND kind='tool_result'",
            (evidence_id,),
        ).fetchone()
        return dict(row) if row else None

    def evidence_records(self) -> list[dict]:
        """All tool_result evidence rows as projected metadata dicts —
        evidence_id/tool/action/detail/size_bytes/coverage.status/created.
        NO payloads (content stays on disk under artifacts/evidence/)."""
        out: list[dict] = []
        for r in self._conn.execute(
                "SELECT * FROM evidence WHERE kind='tool_result'"
                " ORDER BY created DESC").fetchall():
            d = dict(r)
            try:
                cov = json.loads(d.get("coverage_json") or "")
            except (TypeError, ValueError):
                cov = {}
            out.append({
                "evidence_id": d.get("id") or "",
                "tool": d.get("tool") or "",
                "action": d.get("action") or "",
                "detail": d.get("detail") or "complete",
                "size_bytes": int(d.get("size_bytes") or 0),
                "coverage": ({"status": cov.get("status")}
                             if isinstance(cov, dict) and cov.get("status")
                             else None),
                "created": d.get("created"),
            })
        return out

    def delete_evidence_record(self, evidence_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM evidence WHERE id=? AND kind='tool_result'",
            (evidence_id,),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def delete_all_evidence_records(self) -> int:
        """Delete every unattached tool_result row (finding-attached
        evidence added via add_evidence is NOT touched)."""
        cur = self._conn.execute(
            "DELETE FROM evidence WHERE kind='tool_result'")
        self._conn.commit()
        return cur.rowcount

    # ---------------------------------------------------------------- notes ----

    def annotate(self, content: str, *, agent_id: str = "",
                 artifact_sha: str = "", module: str = "", address: str = "",
                 function: str = "", target: str = "",
                 kind: str = "context") -> str:
        nid = uuid.uuid4().hex[:12]
        self._conn.execute(
            "INSERT INTO notes (id, agent_id, artifact_sha, module, address,"
            " function, target, kind, content, created)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (nid, agent_id, artifact_sha, module, address, function, target,
             kind, content, _now()),
        )
        self._conn.commit()
        return nid

    def notes_for(self, *, artifact_sha: str = "", module: str = "",
                  address: str = "", target: str = "",
                  limit: int = 50) -> list[Note]:
        clauses, vals = ["1=1"], []
        for col, v in (("artifact_sha", artifact_sha), ("module", module),
                       ("address", address), ("target", target)):
            if v:
                clauses.append(f"{col}=?"); vals.append(v)
        q = ("SELECT * FROM notes WHERE " + " AND ".join(clauses)
             + " ORDER BY created DESC LIMIT ?")
        vals.append(int(limit))
        return [Note(**dict(r)) for r in self._conn.execute(q, vals).fetchall()]

    # --------------------------------------------------------- tool_events ----

    def event(self, tool: str, action: str, *, agent_id: str = "",
              session_id: str = "", artifact_sha: str = "", target: str = "",
              module: str = "", address: str = "", summary: str = "") -> str:
        """Write one breadcrumb row. Failure to persist an event never
        raises — the caller is a real tool that succeeded on its main
        path, and losing a breadcrumb is preferable to losing a tool
        response. Any exception is logged and swallowed."""
        try:
            eid = uuid.uuid4().hex[:12]
            self._conn.execute(
                "INSERT INTO tool_events (id, agent_id, session_id,"
                " artifact_sha, tool, action, target, module, address,"
                " summary, created)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (eid, agent_id, session_id, artifact_sha, tool, action,
                 target, module, address, summary[:2000], _now()),
            )
            self._conn.commit()
            return eid
        except sqlite3.Error as exc:
            log.warning("ledger.event dropped (%s %s): %s", tool, action, exc)
            return ""

    def events_for(self, *, artifact_sha: str = "", module: str = "",
                   target: str = "", limit: int = 50) -> list[ToolEvent]:
        clauses, vals = ["1=1"], []
        for col, v in (("artifact_sha", artifact_sha), ("module", module),
                       ("target", target)):
            if v:
                clauses.append(f"{col}=?"); vals.append(v)
        q = ("SELECT * FROM tool_events WHERE " + " AND ".join(clauses)
             + " ORDER BY created DESC LIMIT ?")
        vals.append(int(limit))
        return [ToolEvent(**dict(r)) for r in self._conn.execute(q, vals).fetchall()]
