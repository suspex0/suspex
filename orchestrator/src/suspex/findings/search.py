"""`about()` cross-scope KB view + FTS5 ``search()`` mixin.

Split from ``findings.py`` to keep individual modules under 600 lines.
"""

from __future__ import annotations

from typing import Any


class SearchMixin:
    """Mixin providing the cross-scope ``about`` summary and the FTS5
    ``search`` query on ``FindingsLedger``. Assumes the composite class
    brings ``self._conn`` plus the artifact-alias helpers from
    :class:`ArtifactsMixin` and ``_count`` from :class:`LedgerCore`."""

    def about(self, *, sha: str = "", alias: str = "", module: str = "",
              address: str = "", function: str = "", target: str = "",
              limit: int = 50) -> dict[str, Any]:
        """One-call "what do we know about X". Any subset of scoping keys
        is accepted; empty call raises ``ValueError`` so a caller does not
        accidentally fetch the whole KB."""
        if not any([sha, alias, module, address, function, target]):
            raise ValueError(
                "about() requires at least one scoping key: sha, alias, module,"
                " address, function or target"
            )
        # Resolve aliases → sha set
        sha_set: set[str] = set()
        if sha:
            sha_set.add(sha)
        if alias:
            for s in self.artifact_by_alias(alias):
                sha_set.add(s)

        artifacts_out: list[dict] = []
        if sha_set:
            for s in sha_set:
                for a in self.artifacts_list(sha=s):
                    d = a.__dict__
                    d["findings_count"] = self._count(
                        "findings", "artifact_sha=?", (s,))
                    d["notes_count"] = self._count(
                        "notes", "artifact_sha=?", (s,))
                    d["events_count"] = self._count(
                        "tool_events", "artifact_sha=?", (s,))
                    artifacts_out.append(d)
        elif alias:
            # alias with no artifact yet — still surface it in the summary
            artifacts_out.append({"sha256": "", "name": alias, "aliases": [alias],
                                  "findings_count": 0, "notes_count": 0,
                                  "events_count": 0, "kind": "", "size": 0,
                                  "first_seen": 0, "last_seen": 0,
                                  "origin": "alias_only"})

        findings_out = self._collect_findings(sha_set, module, address,
                                              function, target, limit)
        notes_out = self._collect_notes(sha_set, module, address, target, limit)
        events_out = self._collect_events(sha_set, module, target, limit)
        ida_out = self._collect_ida_sessions(sha_set, limit)

        return {
            "artifacts": artifacts_out,
            "findings": findings_out,
            "notes": notes_out,
            "events": events_out,
            "ida_sessions": ida_out,
        }

    def _collect_findings(self, sha_set: set[str], module: str, address: str,
                          function: str, target: str, limit: int) -> list[dict]:
        clauses: list[str] = []
        vals: list = []
        if sha_set:
            clauses.append("artifact_sha IN (" + ",".join(["?"] * len(sha_set)) + ")")
            vals.extend(sha_set)
        if module:
            clauses.append("module=?"); vals.append(module)
        if address:
            clauses.append("address=?"); vals.append(address)
        if function:
            clauses.append("function=?"); vals.append(function)
        if target:
            clauses.append("session_id IN (SELECT id FROM sessions WHERE target=?)")
            vals.append(target)
        if not clauses:
            return []
        q = ("SELECT id, session_id, severity, title, description, status,"
             " agent_id, artifact_sha, module, address, function, stale,"
             " created, supersedes FROM findings WHERE "
             + " OR ".join(clauses)
             + " ORDER BY created DESC LIMIT ?")
        vals.append(int(limit))
        return [dict(r) for r in self._conn.execute(q, vals).fetchall()]

    def _collect_notes(self, sha_set: set[str], module: str, address: str,
                       target: str, limit: int) -> list[dict]:
        clauses: list[str] = []
        vals: list = []
        if sha_set:
            clauses.append("artifact_sha IN (" + ",".join(["?"] * len(sha_set)) + ")")
            vals.extend(sha_set)
        if module:
            clauses.append("module=?"); vals.append(module)
        if address:
            clauses.append("address=?"); vals.append(address)
        if target:
            clauses.append("target=?"); vals.append(target)
        if not clauses:
            return []
        q = ("SELECT * FROM notes WHERE " + " OR ".join(clauses)
             + " ORDER BY created DESC LIMIT ?")
        vals.append(int(limit))
        return [dict(r) for r in self._conn.execute(q, vals).fetchall()]

    def _collect_events(self, sha_set: set[str], module: str, target: str,
                        limit: int) -> list[dict]:
        clauses: list[str] = []
        vals: list = []
        if sha_set:
            clauses.append("artifact_sha IN (" + ",".join(["?"] * len(sha_set)) + ")")
            vals.extend(sha_set)
        if module:
            clauses.append("module=?"); vals.append(module)
        if target:
            clauses.append("target=?"); vals.append(target)
        if not clauses:
            return []
        q = ("SELECT * FROM tool_events WHERE " + " OR ".join(clauses)
             + " ORDER BY created DESC LIMIT ?")
        vals.append(int(limit))
        return [dict(r) for r in self._conn.execute(q, vals).fetchall()]

    def _collect_ida_sessions(self, sha_set: set[str], limit: int) -> list[dict]:
        if not sha_set:
            return []
        q = ("SELECT * FROM ida_sessions WHERE artifact_sha IN ("
             + ",".join(["?"] * len(sha_set)) + ")"
             + " ORDER BY last_touched DESC LIMIT ?")
        vals = list(sha_set) + [int(limit)]
        return [dict(r) for r in self._conn.execute(q, vals).fetchall()]

    # --------------------------------------------------------------- search ----

    def search(self, q: str, *, since: float | None = None, agent: str = "",
               kind: str = "", limit: int = 50) -> list[dict]:
        """FTS5 full-text search over findings + notes + evidence."""
        if not q or not self.fts_available():
            return []
        base = "SELECT kind, ref_id, snippet(fts, 3, '[', ']', ' ... ', 12) AS snippet FROM fts WHERE fts MATCH ?"
        vals: list = [q]
        if kind:
            base += " AND kind=?"; vals.append(kind)
        base += " LIMIT ?"; vals.append(int(limit))
        raw = [dict(r) for r in self._conn.execute(base, vals).fetchall()]
        # enrich with created + agent_id from the source row so `since` /
        # `agent` filters work in Python (FTS body doesn't include them)
        out: list[dict] = []
        for r in raw:
            src = self._enrich_search_row(r)
            if src is None:
                continue
            if since is not None and float(src.get("created") or 0) < since:
                continue
            if agent and str(src.get("agent_id") or "") != agent:
                continue
            out.append({**r, **src})
        return out

    def _enrich_search_row(self, r: dict) -> dict | None:
        kind = r["kind"]; rid = r["ref_id"]
        if kind == "finding":
            row = self._conn.execute(
                "SELECT created, agent_id, title AS source_title FROM findings WHERE id=?",
                (rid,),
            ).fetchone()
        elif kind == "note":
            row = self._conn.execute(
                "SELECT created, agent_id, kind AS source_title FROM notes WHERE id=?",
                (rid,),
            ).fetchone()
        elif kind == "evidence":
            row = self._conn.execute(
                "SELECT created, '' AS agent_id, kind AS source_title FROM evidence WHERE id=?",
                (rid,),
            ).fetchone()
        else:
            return None
        return dict(row) if row else None
