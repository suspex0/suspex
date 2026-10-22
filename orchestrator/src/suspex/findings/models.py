"""Dataclasses and small module-scope helpers for the findings ledger.

Row shapes returned by ``FindingsLedger`` queries plus the wall-clock
``_now`` shim used everywhere as the ``created`` / ``updated`` source,
and two tiny formatting helpers (``_hex`` for compact ids,
``_kind_from_ext`` for the on-disk artifact classifier).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    session_id: str
    severity: str
    title: str
    description: str
    status: str
    refs: str
    created: float
    updated: float
    artifact_sha: str = ""
    module: str = ""
    address: str = ""
    function: str = ""
    agent_id: str = ""
    stale: int = 0
    supersedes: str = ""


@dataclass
class Evidence:
    id: str
    finding_id: str
    kind: str
    content: str
    created: float
    # Evidence-envelope columns (Part 3, additive migration in
    # ledger._migrate_schema). Unattached tool_result records carry
    # digest + provenance of the producing call; finding-attached rows
    # (add_evidence) keep these defaulted empty.
    digest: str = ""
    operation: str = ""
    tool: str = ""
    action: str = ""
    coverage_json: str = ""
    size_bytes: int = 0
    detail: str = "complete"
    parent_id: str = ""


@dataclass
class Note:
    id: str
    agent_id: str
    artifact_sha: str
    module: str
    address: str
    function: str
    target: str
    kind: str
    content: str
    created: float


@dataclass
class ToolEvent:
    id: str
    agent_id: str
    session_id: str
    artifact_sha: str
    tool: str
    action: str
    target: str
    module: str
    address: str
    summary: str
    created: float


@dataclass
class Artifact:
    sha256: str
    name: str
    kind: str
    size: int
    first_seen: float
    last_seen: float
    origin: str
    aliases: list[str] = field(default_factory=list)


@dataclass
class IdaSession:
    ida_session_name: str
    artifact_sha: str
    opened_by_agent: str
    opened_at: float
    last_touched: float
    status: str
    on_disk_path: str
    # 'ida' | 'ghidra' — which engine owns this analysis session.
    engine: str = "ida"


def _now() -> float:
    return time.time()


def _hex(s: str, n: int = 12) -> str:
    return hashlib.sha1(s.encode("utf-8", "surrogatepass")).hexdigest()[:n]


def _kind_from_ext(name: str) -> str:
    """Coarse artifact-kind classifier: kernel driver, DLL, executable,
    crashdump, IDA database, or generic ``bin``."""
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
