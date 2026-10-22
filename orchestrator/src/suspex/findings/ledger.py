"""Ledger core: schema/migration, session and finding CRUD.

Split from ``findings.py`` to keep individual modules under 600 lines.
This module also assembles the final :class:`FindingsLedger` by mixing
in the notes/events, artifacts, search and report modules.
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from pathlib import Path

from .artifacts import ArtifactsMixin
from .models import Finding, _kind_from_ext, _now
from .notes_events import NotesEventsMixin
from .report import ReportMixin
from .search import SearchMixin

log = logging.getLogger(__name__)

# v0.18 schema. The legacy tables (sessions/findings/evidence) still exist
# with their original columns; new columns are added with ALTER TABLE at
# migration time so a pre-v0.18 DB upgrades on first open without losing
# rows. See ``_migrate_schema`` for the delta application.
SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target TEXT,
    started REAL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'open',
    refs TEXT DEFAULT '',
    created REAL,
    updated REAL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    kind TEXT,
    content TEXT,
    created REAL,
    digest TEXT DEFAULT '',
    operation TEXT DEFAULT '',
    tool TEXT DEFAULT '',
    action TEXT DEFAULT '',
    coverage_json TEXT DEFAULT '',
    size_bytes INTEGER DEFAULT 0,
    detail TEXT DEFAULT 'complete',
    parent_id TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY,
    name TEXT,
    kind TEXT,
    size INTEGER,
    first_seen REAL,
    last_seen REAL,
    origin TEXT
);

CREATE TABLE IF NOT EXISTS artifact_aliases (
    sha256 TEXT,
    alias TEXT,
    first_seen REAL,
    PRIMARY KEY (sha256, alias)
);
CREATE INDEX IF NOT EXISTS idx_alias ON artifact_aliases(alias);

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    agent_id TEXT DEFAULT '',
    artifact_sha TEXT DEFAULT '',
    module TEXT DEFAULT '',
    address TEXT DEFAULT '',
    function TEXT DEFAULT '',
    target TEXT DEFAULT '',
    kind TEXT DEFAULT 'context',
    content TEXT,
    created REAL
);
CREATE INDEX IF NOT EXISTS idx_notes_sha ON notes(artifact_sha);
CREATE INDEX IF NOT EXISTS idx_notes_module ON notes(module);
CREATE INDEX IF NOT EXISTS idx_notes_address ON notes(address);

CREATE TABLE IF NOT EXISTS tool_events (
    id TEXT PRIMARY KEY,
    agent_id TEXT DEFAULT '',
    session_id TEXT DEFAULT '',
    artifact_sha TEXT DEFAULT '',
    tool TEXT,
    action TEXT,
    target TEXT DEFAULT '',
    module TEXT DEFAULT '',
    address TEXT DEFAULT '',
    summary TEXT,
    created REAL
);
CREATE INDEX IF NOT EXISTS idx_events_sha ON tool_events(artifact_sha);
CREATE INDEX IF NOT EXISTS idx_events_module ON tool_events(module);
CREATE INDEX IF NOT EXISTS idx_events_target ON tool_events(target);

CREATE TABLE IF NOT EXISTS ida_sessions (
    ida_session_name TEXT PRIMARY KEY,
    artifact_sha TEXT DEFAULT '',
    opened_by_agent TEXT DEFAULT '',
    opened_at REAL,
    last_touched REAL,
    status TEXT DEFAULT 'live',
    on_disk_path TEXT DEFAULT '',
    engine TEXT DEFAULT 'ida'
);
CREATE INDEX IF NOT EXISTS idx_ida_sha ON ida_sessions(artifact_sha);
"""

# Columns to ADD to the v1 findings table when upgrading in place. Each is
# (name, type, default) applied via ``ALTER TABLE findings ADD COLUMN``.
_FINDINGS_V2_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("artifact_sha", "TEXT", "''"),
    ("module", "TEXT", "''"),
    ("address", "TEXT", "''"),
    ("function", "TEXT", "''"),
    ("agent_id", "TEXT", "''"),
    ("stale", "INTEGER", "0"),
    ("supersedes", "TEXT", "''"),
)

# Part 3 (evidence envelope): columns to ADD to the v1 evidence table.
# Fresh DBs are born with them (SCHEMA above); older DBs are migrated in
# _migrate_evidence_columns with a backup taken before the first ALTER.
_EVIDENCE_V2_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("digest", "TEXT", "''"),
    ("operation", "TEXT", "''"),
    ("tool", "TEXT", "''"),
    ("action", "TEXT", "''"),
    ("coverage_json", "TEXT", "''"),
    ("size_bytes", "INTEGER", "0"),
    ("detail", "TEXT", "'complete'"),
    ("parent_id", "TEXT", "''"),
)

# PRAGMA user_version stamped once the evidence columns are in place; the
# migration short-circuits when the DB already reports this version.
EVIDENCE_SCHEMA_VERSION = 2


class LedgerCore:
    """SQLite-backed shared knowledge base.

    Instance is *not* threadsafe on writes; every MCP request already runs
    through ``_guard`` which serializes per-tool, and the SDK's plugin
    runner opens its own ledger handle. Read paths (`about`, `search`,
    `list_findings`, etc.) are pure SELECTs and safe to interleave.
    """

    def __init__(self, db_path: str | Path,
                 *, artifacts_dir: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if str(db_path) != ":memory:" else None
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
        else:
            self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate_schema()
        self._install_fts()
        self._conn.commit()
        # v0.18 Phase 4a: cheap first-boot backfill fallback. When the
        # artifacts table is still empty and an artifacts_dir is passed
        # in, walk one level of `<sha>/<name>` layout and register each
        # binary. This is a cheap backfill so a fresh knowledge base
        # picks up binaries already sitting in the artifacts dir.
        if artifacts_dir is not None:
            try:
                self._backfill_artifacts_dir(Path(artifacts_dir))
            except Exception as exc:  # pragma: no cover
                log.warning("[backfill] fallback skipped: %s", exc)

    def _backfill_artifacts_dir(self, adir: Path) -> None:
        if not adir.exists() or not adir.is_dir():
            return
        n_existing = self._conn.execute(
            "SELECT COUNT(*) AS n FROM artifacts").fetchone()["n"]
        if n_existing > 0:
            return
        import re as _re
        _SHA = _re.compile(r"^[0-9a-f]{64}$")
        added = 0
        for entry in adir.iterdir():
            if not entry.is_dir() or not _SHA.match(entry.name):
                continue
            for f in entry.iterdir():
                if not f.is_file():
                    continue
                name = f.name
                try:
                    size = f.stat().st_size
                except OSError:
                    continue
                self.upsert_artifact(
                    entry.name, name=name,
                    kind=_kind_from_ext(name), size=size,
                    origin="backfill_onboot", alias=name,
                )
                added += 1
        if added:
            log.info("[backfill] populated %d artifacts from %s", added, adir)

    def close(self) -> None:
        self._conn.close()

    # ---------------------------------------------------------------- migration ----

    def _migrate_schema(self) -> None:
        """Idempotent additive migration. Adds v2 columns to ``findings``
        that don't yet exist. Never drops columns; a pre-v0.18 DB comes
        out fully backward-compatible with any code still reading the
        legacy shape."""
        existing = {r["name"] for r in self._conn.execute("PRAGMA table_info(findings)")}
        added: list[str] = []
        for col, typ, default in _FINDINGS_V2_COLUMNS:
            if col in existing:
                continue
            self._conn.execute(
                f"ALTER TABLE findings ADD COLUMN {col} {typ} DEFAULT {default}"
            )
            added.append(col)
        if added:
            log.info("[migrate] findings.db schema v2 applied: added %s", added)
        # ghidra_manage: the analysis-session table doubles for Ghidra
        # sessions — an `engine` column preserves which engine produced
        # them (a renamed-decompile from IDA vs Ghidra are different
        # claims). Existing DBs default to 'ida' for every prior row.
        ida_cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(ida_sessions)")}
        if "engine" not in ida_cols:
            self._conn.execute(
                "ALTER TABLE ida_sessions ADD COLUMN engine TEXT DEFAULT 'ida'"
            )
            log.info("[migrate] ida_sessions gained engine column")
        self._migrate_evidence_columns()

    def _migrate_evidence_columns(self) -> None:
        """Part 3 additive evidence migration. Idempotent: skipped entirely
        when ``PRAGMA user_version`` already reports EVIDENCE_SCHEMA_VERSION;
        otherwise missing columns are ALTERed in (with a
        ``findings.db.bak-<date>`` backup taken before the first ALTER,
        same discipline as ``.bak-premerge``) and the version stamped."""
        try:
            row = self._conn.execute("PRAGMA user_version").fetchone()
            if row and int(row["user_version"]) >= EVIDENCE_SCHEMA_VERSION:
                return
        except (sqlite3.Error, TypeError, ValueError, KeyError):
            pass
        existing = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(evidence)")}
        missing = [c for c in _EVIDENCE_V2_COLUMNS if c[0] not in existing]
        if missing:
            self._backup_before_evidence_alter()
            for col, typ, default in missing:
                self._conn.execute(
                    f"ALTER TABLE evidence ADD COLUMN {col} {typ} DEFAULT {default}"
                )
            log.info("[migrate] evidence schema v2 applied: added %s",
                     [c[0] for c in missing])
        self._conn.execute(
            f"PRAGMA user_version = {EVIDENCE_SCHEMA_VERSION}")

    def _backup_before_evidence_alter(self) -> None:
        """Copy ``findings.db`` -> ``findings.db.bak-<date>`` before the
        evidence ALTERs. Best-effort: a failed backup is logged and the
        migration proceeds (the ALTERs are additive and lossless)."""
        if self.db_path is None or not self.db_path.exists():
            return
        import datetime as _dt
        import shutil
        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = self.db_path.with_name(f"{self.db_path.name}.bak-{stamp}")
        if backup.exists():
            return
        try:
            self._conn.commit()
            shutil.copy2(self.db_path, backup)
            log.info("[migrate] evidence migration backup: %s", backup)
        except OSError as exc:
            log.warning("[migrate] evidence backup failed (%s): %s",
                        backup, exc)

    def _install_fts(self) -> None:
        """FTS5 index over findings + notes + evidence. External-content
        table with ``kind`` distinguishing rows; keeps the FTS in sync
        via triggers rather than a rebuild on every write."""
        try:
            self._conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5("
                "kind, ref_id, title, body, tags, tokenize='unicode61')"
            )
        except sqlite3.OperationalError as exc:
            log.warning("[migrate] fts5 unavailable, search() will be disabled: %s", exc)
            return

        # Simple triggers: we only ever INSERT into fts (dedup via
        # ref_id filter on write). UPDATE/DELETE trigger blocks below
        # keep the row set fresh when a finding's title/desc changes.
        self._conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS fts_findings_ai AFTER INSERT ON findings BEGIN
            INSERT INTO fts(kind, ref_id, title, body, tags)
            VALUES ('finding', NEW.id, NEW.title, NEW.description,
                    printf('sha:%s module:%s address:%s function:%s agent:%s',
                        COALESCE(NEW.artifact_sha,''),
                        COALESCE(NEW.module,''),
                        COALESCE(NEW.address,''),
                        COALESCE(NEW.function,''),
                        COALESCE(NEW.agent_id,'')));
        END;
        CREATE TRIGGER IF NOT EXISTS fts_findings_au AFTER UPDATE ON findings BEGIN
            DELETE FROM fts WHERE kind='finding' AND ref_id=OLD.id;
            INSERT INTO fts(kind, ref_id, title, body, tags)
            VALUES ('finding', NEW.id, NEW.title, NEW.description,
                    printf('sha:%s module:%s address:%s function:%s agent:%s',
                        COALESCE(NEW.artifact_sha,''),
                        COALESCE(NEW.module,''),
                        COALESCE(NEW.address,''),
                        COALESCE(NEW.function,''),
                        COALESCE(NEW.agent_id,'')));
        END;
        CREATE TRIGGER IF NOT EXISTS fts_findings_ad AFTER DELETE ON findings BEGIN
            DELETE FROM fts WHERE kind='finding' AND ref_id=OLD.id;
        END;
        CREATE TRIGGER IF NOT EXISTS fts_notes_ai AFTER INSERT ON notes BEGIN
            INSERT INTO fts(kind, ref_id, title, body, tags)
            VALUES ('note', NEW.id, NEW.kind, NEW.content,
                    printf('sha:%s module:%s address:%s function:%s target:%s agent:%s',
                        COALESCE(NEW.artifact_sha,''),
                        COALESCE(NEW.module,''),
                        COALESCE(NEW.address,''),
                        COALESCE(NEW.function,''),
                        COALESCE(NEW.target,''),
                        COALESCE(NEW.agent_id,'')));
        END;
        CREATE TRIGGER IF NOT EXISTS fts_notes_ad AFTER DELETE ON notes BEGIN
            DELETE FROM fts WHERE kind='note' AND ref_id=OLD.id;
        END;
        CREATE TRIGGER IF NOT EXISTS fts_evidence_ai AFTER INSERT ON evidence BEGIN
            INSERT INTO fts(kind, ref_id, title, body, tags)
            VALUES ('evidence', NEW.id, NEW.kind, NEW.content, '');
        END;
        CREATE TRIGGER IF NOT EXISTS fts_evidence_ad AFTER DELETE ON evidence BEGIN
            DELETE FROM fts WHERE kind='evidence' AND ref_id=OLD.id;
        END;
        """)

    def fts_available(self) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='fts'"
        ).fetchone()
        return row is not None

    # -------------------------------------------------------------- sessions ----

    def start_session(self, target: str, notes: str = "") -> str:
        sid = uuid.uuid4().hex[:12]
        self._conn.execute(
            "INSERT INTO sessions (id, target, started, notes) VALUES (?,?,?,?)",
            (sid, target, _now(), notes),
        )
        self._conn.commit()
        return sid

    def sessions(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM sessions ORDER BY started DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- findings ----

    def record(self, session_id: str, severity: str, title: str,
               description: str, refs: str = "",
               *,
               agent_id: str = "",
               artifact_sha: str = "",
               module: str = "",
               address: str = "",
               function: str = "",
               supersedes: str = "") -> str:
        """Insert a finding, return its id. Backward-compatible with the
        pre-v0.18 signature — the extra keyword-only fields default to
        empty strings so existing plugin / SDK / parity callers keep
        working. Use :meth:`record_ex` when you want dedupe with a
        signal about whether an existing row won."""
        fid, _ = self.record_ex(
            session_id, severity, title, description, refs,
            agent_id=agent_id, artifact_sha=artifact_sha, module=module,
            address=address, function=function, supersedes=supersedes,
            dedupe=False,
        )
        return fid

    def record_ex(self, session_id: str, severity: str, title: str,
                  description: str, refs: str = "",
                  *,
                  agent_id: str = "",
                  artifact_sha: str = "",
                  module: str = "",
                  address: str = "",
                  function: str = "",
                  supersedes: str = "",
                  dedupe: bool = True) -> tuple[str, str | None]:
        """Insert a finding with optional dedupe. When ``dedupe`` is True
        and an *open* finding already exists with the same
        ``(title, artifact_sha, address)`` signature, returns that
        existing id as the second element and skips the insert.
        Returns ``(finding_id, duplicate_of_or_None)``."""
        if dedupe and title:
            row = self._conn.execute(
                "SELECT id FROM findings WHERE status='open' AND title=? "
                "AND COALESCE(artifact_sha,'')=? AND COALESCE(address,'')=?",
                (title, artifact_sha or "", address or ""),
            ).fetchone()
            if row:
                return row["id"], row["id"]
        fid = uuid.uuid4().hex[:12]
        now = _now()
        self._conn.execute(
            "INSERT INTO findings (id, session_id, severity, title, description,"
            " status, refs, created, updated, artifact_sha, module, address,"
            " function, agent_id, stale, supersedes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
            (fid, session_id, severity, title, description, "open", refs,
             now, now, artifact_sha, module, address, function, agent_id,
             supersedes),
        )
        self._conn.commit()
        return fid, None

    def update(self, finding_id: str, status: str | None = None,
               title: str | None = None, description: str | None = None,
               severity: str | None = None,
               *,
               stale: int | None = None) -> None:
        sets, vals = [], []
        for col, v in (("status", status), ("title", title),
                       ("description", description), ("severity", severity),
                       ("stale", stale)):
            if v is not None:
                sets.append(f"{col}=?")
                vals.append(v)
        if not sets:
            return
        sets.append("updated=?")
        vals.append(_now())
        vals.append(finding_id)
        self._conn.execute(
            f"UPDATE findings SET {', '.join(sets)} WHERE id=?", vals
        )
        self._conn.commit()

    def link(self, finding_id: str, *, artifact_sha: str | None = None,
             module: str | None = None, address: str | None = None,
             function: str | None = None) -> bool:
        """Attach structured scoping keys to an existing finding."""
        sets, vals = [], []
        for col, v in (("artifact_sha", artifact_sha), ("module", module),
                       ("address", address), ("function", function)):
            if v is not None:
                sets.append(f"{col}=?")
                vals.append(v)
        if not sets:
            return False
        sets.append("updated=?")
        vals.append(_now())
        vals.append(finding_id)
        cur = self._conn.execute(
            f"UPDATE findings SET {', '.join(sets)} WHERE id=?", vals
        )
        self._conn.commit()
        return cur.rowcount > 0

    def mark_stale(self, *, finding_id: str | None = None,
                   filter_module: str | None = None,
                   filter_target: str | None = None,
                   reason: str = "") -> int:
        """Mark one finding (by id) OR every finding matching module/target
        as stale. Returns the number of rows updated."""
        clauses, vals = ["stale=0"], []
        if finding_id:
            clauses.append("id=?"); vals.append(finding_id)
        elif filter_module:
            clauses.append("module=?"); vals.append(filter_module)
        elif filter_target:
            clauses.append("session_id IN (SELECT id FROM sessions WHERE target=?)")
            vals.append(filter_target)
        else:
            return 0
        where = " AND ".join(clauses)
        cur = self._conn.execute(
            f"UPDATE findings SET stale=1, updated=? WHERE {where}",
            [_now(), *vals],
        )
        # attach a reason as evidence when a specific id was named
        if finding_id and reason:
            self.add_evidence(finding_id, "stale_reason", reason)
        self._conn.commit()
        return cur.rowcount

    def list_findings(self, session_id: str | None = None,
                      status: str | None = None) -> list[Finding]:
        q = "SELECT * FROM findings WHERE 1=1"
        vals: list = []
        if session_id:
            q += " AND session_id=?"
            vals.append(session_id)
        if status:
            q += " AND status=?"
            vals.append(status)
        q += " ORDER BY created"
        return [Finding(**dict(r)) for r in self._conn.execute(q, vals).fetchall()]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return Finding(**dict(row)) if row else None

    # ---------------------------------------------------------------- helpers ----

    def _count(self, table: str, where: str, vals: tuple) -> int:
        row = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", vals
        ).fetchone()
        return int(row["n"] if row else 0)


class FindingsLedger(NotesEventsMixin, ArtifactsMixin, SearchMixin,
                     ReportMixin, LedgerCore):
    """SQLite-backed shared knowledge base.

    Composed from :class:`LedgerCore` plus mixins for the notes/events,
    artifact-index, cross-scope ``about`` / ``search`` and report
    surfaces. See :class:`LedgerCore` for the constructor and threading
    contract.
    """
