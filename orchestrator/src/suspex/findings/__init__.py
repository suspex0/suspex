"""SQLite findings + shared-knowledge ledger.

v0.18 reshapes the ledger from a per-agent finding log into a cross-agent
knowledge base. Findings, notes, tool-event breadcrumbs, an artifact
index (sha256 + aliases) and IDA-session records all live here; the
``about()`` API answers "what do we already know about this binary /
module / address" in one call so a second agent does not re-derive what
a peer already learned.

Schema migration is additive: on first open every ``ALTER TABLE`` /
``CREATE TABLE IF NOT EXISTS`` runs idempotently, existing rows survive,
and rows written by pre-v0.18 clients still read fine.

This package is the facade for the split modules that used to live in a
single ``findings.py``; every public name a pre-split caller imported
still resolves from ``suspex.findings``.
"""

from __future__ import annotations

from .artifacts import ArtifactsMixin
from .ledger import (
    SCHEMA,
    FindingsLedger,
    LedgerCore,
    _FINDINGS_V2_COLUMNS,
)
from .models import (
    Artifact,
    Evidence,
    Finding,
    IdaSession,
    Note,
    ToolEvent,
    _hex,
    _kind_from_ext,
    _now,
)
from .notes_events import NotesEventsMixin
from .report import ReportMixin
from .search import SearchMixin

__all__ = [
    "Artifact",
    "ArtifactsMixin",
    "Evidence",
    "Finding",
    "FindingsLedger",
    "IdaSession",
    "LedgerCore",
    "Note",
    "NotesEventsMixin",
    "ReportMixin",
    "SCHEMA",
    "SearchMixin",
    "ToolEvent",
    "_FINDINGS_V2_COLUMNS",
    "_hex",
    "_kind_from_ext",
    "_now",
]
