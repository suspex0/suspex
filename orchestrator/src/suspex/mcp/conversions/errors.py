"""Errors surfaced by the conversion primitives."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConversionError(Exception):
    """Every failure surfaced by this module carries a `kind` slug so the
    caller can render {ok:false, kind, error, hint} without regexing English.
    """

    def __init__(self, kind: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint
