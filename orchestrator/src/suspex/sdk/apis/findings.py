"""FindingsApi: scripts file their own results into the ledger."""

from __future__ import annotations

from typing import Any

from ..reader import SuspexError


class FindingsApi:
    """Scripts file their own results into the ledger."""

    def __init__(self, ledger: Any, session_id: str) -> None:
        self._ledger = ledger
        self._session_id = session_id

    def record(self, severity: str, title: str, description: str, refs: str = "") -> str:
        if self._ledger is None:
            raise SuspexError("no findings ledger in this context")
        sid = self._session_id or self._ledger.start_session("sdk")
        return self._ledger.record(sid, severity, title, description, refs)

    def evidence(self, finding_id: str, kind: str, content: str) -> str:
        if self._ledger is None:
            raise SuspexError("no findings ledger in this context")
        return self._ledger.add_evidence(finding_id, kind, content)
