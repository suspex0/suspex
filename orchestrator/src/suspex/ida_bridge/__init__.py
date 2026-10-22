"""Facade for the ``suspex.ida_bridge`` package (mechanical split of the
former ``ida_bridge.py``).

Key runtime facts this bridge is built around (from ida-pro-mcp docs):
- the supervisor is spawned as ``uv run idalib-mcp --stdio`` (MCP over stdio)
- ``idb_open(input_path, mode, run_auto_analysis, preferred_session_id)``
  returns a session ID; EVERY subsequent tool call requires
  ``database=<session_id>``, file paths are not accepted
- worker processes are detached and persistent: they outlive the supervisor
  and are adopted by a later supervisor opening the same path. We therefore
  never assume killing the supervisor closes databases; use idb_list /
  idb_close.
- idalib needs IDA Pro 8.3+/9 with an activated idalib; failures surface
  here as actionable :class:`IdaBridgeError` messages, never as opaque
  MCP timeouts.

Public surface (kept re-exported for backwards compatibility with every
existing caller / test):
    :class:`IdaBridge`, :class:`IdaBridgeError`, :class:`IdaConfigLite`
    :data:`IDA_MANIFEST_VERSION`, :data:`MCP_PROTOCOL_VERSION`
    :data:`_NON_SESSION_ACTIONS`, :data:`_SESSION_NAME_RE`
    :func:`_valid_session_name`, :func:`_classify_symbols`,
    :func:`_safe_int`, :func:`_classify_pdb`, :func:`_default_manifest_path`
"""

from __future__ import annotations

from .bridge import IdaBridge
from .config import IDA_MANIFEST_VERSION, IdaConfigLite, _default_manifest_path
from .errors import IdaBridgeError
from .helpers import (
    _NON_SESSION_ACTIONS,
    _SESSION_NAME_RE,
    _classify_pdb,
    _classify_symbols,
    _safe_int,
    _valid_session_name,
)
from .lifecycle import MCP_PROTOCOL_VERSION

__all__ = [
    "IDA_MANIFEST_VERSION",
    "IdaBridge",
    "IdaBridgeError",
    "IdaConfigLite",
    "MCP_PROTOCOL_VERSION",
    "_NON_SESSION_ACTIONS",
    "_SESSION_NAME_RE",
    "_classify_pdb",
    "_classify_symbols",
    "_default_manifest_path",
    "_safe_int",
    "_valid_session_name",
]
