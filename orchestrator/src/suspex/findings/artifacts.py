"""Artifact index and IDA-session tracking mixin for ``FindingsLedger``.

Split from ``findings.py`` to keep individual modules under 600 lines.
"""

from __future__ import annotations

import logging
import sqlite3

from .models import Artifact, IdaSession, _now

log = logging.getLogger(__name__)


class ArtifactsMixin:
    """Mixin providing artifact-index and IDA-session methods on
    ``FindingsLedger``. Assumes the composite class brings a
    ``self._conn`` sqlite3 connection (from :class:`LedgerCore`)."""

    def upsert_artifact(self, sha256: str, *, name: str = "", kind: str = "",
                        size: int = 0, origin: str = "manual",
                        alias: str | None = None) -> None:
        """Insert or refresh an artifact row and, if ``alias`` (defaults to
        ``name``) is set, ensure the alias mapping exists too. Multiple
        aliases per sha are supported — call again with a different
        ``alias`` to accumulate."""
        if not sha256:
            return
        try:
            now = _now()
            row = self._conn.execute(
                "SELECT sha256, first_seen FROM artifacts WHERE sha256=?",
                (sha256,),
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE artifacts SET name=COALESCE(NULLIF(?, ''), name),"
                    " kind=COALESCE(NULLIF(?, ''), kind),"
                    " size=CASE WHEN ?>0 THEN ? ELSE size END,"
                    " last_seen=?"
                    " WHERE sha256=?",
                    (name, kind, size, size, now, sha256),
                )
            else:
                self._conn.execute(
                    "INSERT INTO artifacts (sha256, name, kind, size,"
                    " first_seen, last_seen, origin) VALUES (?,?,?,?,?,?,?)",
                    (sha256, name, kind, size, now, now, origin),
                )
            al = alias if alias is not None else name
            if al:
                self._conn.execute(
                    "INSERT OR IGNORE INTO artifact_aliases"
                    " (sha256, alias, first_seen) VALUES (?,?,?)",
                    (sha256, al, now),
                )
            self._conn.commit()
        except sqlite3.Error as exc:
            log.warning("upsert_artifact(%s) failed: %s", sha256[:12], exc)

    def artifact_aliases(self, sha256: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT alias FROM artifact_aliases WHERE sha256=? ORDER BY first_seen",
            (sha256,),
        ).fetchall()
        return [r["alias"] for r in rows]

    def artifacts_list(self, *, alias: str = "", sha: str = "",
                       kind: str = "", limit: int = 100) -> list[Artifact]:
        clauses, vals = ["1=1"], []
        if sha:
            clauses.append("a.sha256=?"); vals.append(sha)
        if kind:
            clauses.append("a.kind=?"); vals.append(kind)
        if alias:
            # match either the primary name or any alias
            clauses.append(
                "(a.name=? OR a.sha256 IN (SELECT sha256 FROM artifact_aliases WHERE alias=?))"
            )
            vals.extend([alias, alias])
        q = ("SELECT a.* FROM artifacts a WHERE " + " AND ".join(clauses)
             + " ORDER BY a.last_seen DESC LIMIT ?")
        vals.append(int(limit))
        out: list[Artifact] = []
        for r in self._conn.execute(q, vals).fetchall():
            art = Artifact(**{k: r[k] for k in ("sha256", "name", "kind",
                              "size", "first_seen", "last_seen", "origin")})
            art.aliases = self.artifact_aliases(art.sha256)
            out.append(art)
        return out

    def artifact_by_alias(self, alias: str) -> list[str]:
        """Return the list of sha256s known under ``alias``."""
        rows = self._conn.execute(
            "SELECT sha256 FROM artifact_aliases WHERE alias=? ORDER BY first_seen",
            (alias,),
        ).fetchall()
        # also match direct artifact.name
        extra = self._conn.execute(
            "SELECT sha256 FROM artifacts WHERE name=?", (alias,),
        ).fetchall()
        seen: set[str] = set()
        out: list[str] = []
        for r in list(rows) + list(extra):
            if r["sha256"] in seen:
                continue
            seen.add(r["sha256"])
            out.append(r["sha256"])
        return out

    # -------------------------------------------------------- ida_sessions ----

    def open_ida_session(self, name: str, *, artifact_sha: str = "",
                         opened_by_agent: str = "",
                         on_disk_path: str = "",
                         engine: str = "ida") -> None:
        now = _now()
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO ida_sessions"
                " (ida_session_name, artifact_sha, opened_by_agent,"
                " opened_at, last_touched, status, on_disk_path, engine)"
                " VALUES (?, ?, ?,"
                "  COALESCE((SELECT opened_at FROM ida_sessions WHERE ida_session_name=?), ?),"
                "  ?, 'live', ?, ?)",
                (name, artifact_sha, opened_by_agent, name, now, now,
                 on_disk_path, engine),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            log.warning("open_ida_session(%s) failed: %s", name, exc)

    def touch_ida_session(self, name: str) -> None:
        try:
            self._conn.execute(
                "UPDATE ida_sessions SET last_touched=? WHERE ida_session_name=?",
                (_now(), name),
            )
            self._conn.commit()
        except sqlite3.Error:
            pass

    def close_ida_session(self, name: str) -> None:
        try:
            self._conn.execute(
                "UPDATE ida_sessions SET status='closed', last_touched=?"
                " WHERE ida_session_name=?",
                (_now(), name),
            )
            self._conn.commit()
        except sqlite3.Error:
            pass

    def ida_sessions_for(self, *, artifact_sha: str = "",
                         limit: int = 50) -> list[IdaSession]:
        clauses, vals = ["1=1"], []
        if artifact_sha:
            clauses.append("artifact_sha=?"); vals.append(artifact_sha)
        q = ("SELECT * FROM ida_sessions WHERE " + " AND ".join(clauses)
             + " ORDER BY last_touched DESC LIMIT ?")
        vals.append(int(limit))
        return [IdaSession(**dict(r)) for r in self._conn.execute(q, vals).fetchall()]
