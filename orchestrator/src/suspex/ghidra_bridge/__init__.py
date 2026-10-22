"""Facade for the ``suspex.ghidra_bridge`` package — Ghidra's structural
twin of ``suspex.ida_bridge``.

Key runtime facts this bridge is built around:

- the supervisor is spawned as ``python ghidra_stdio_shim.py`` (MCP over
  stdio) — the ``ghidra_shim`` package manages ONE shared backend
  process (JVM + shared Ghidra project) hosting N programs.
- ``ghidra_open(input_path, run_auto_analysis, preferred_session_id)``
  returns a session ID; every subsequent tool call requires
  ``database=<session_id>`` — the shim multiplexes on it and injects the
  matching ``binary_name`` for the backend tool.
- programs persist inside the project file: a backend (JVM) crash drops
  the transport but not the analysis; a later supervisor adopts the
  project contents via ``list_project_binaries``.
- pyghidra needs a JDK + ``GHIDRA_INSTALL_DIR``; failures surface here
  as actionable :class:`GhidraBridgeError` messages, never opaque
  MCP timeouts.

Public surface mirrors ``suspex.ida_bridge``:
    :class:`GhidraBridge`, :class:`GhidraBridgeError`, :class:`GhidraConfigLite`
    :data:`GHIDRA_MANIFEST_VERSION`, :data:`MCP_PROTOCOL_VERSION`
    :data:`_NON_SESSION_ACTIONS`, :data:`_SESSION_NAME_RE`
    :func:`_valid_session_name`, :func:`_classify_symbols`,
    :func:`_safe_int`, :func:`_classify_pdb`, :func:`_default_manifest_path`
"""

from __future__ import annotations

from .bridge import GhidraBridge
from .config import (
    GHIDRA_MANIFEST_VERSION,
    GhidraConfigLite,
    _default_manifest_path,
)
from .errors import GhidraBridgeError
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
    "GHIDRA_MANIFEST_VERSION",
    "GhidraBridge",
    "GhidraBridgeError",
    "GhidraConfigLite",
    "MCP_PROTOCOL_VERSION",
    "_NON_SESSION_ACTIONS",
    "_SESSION_NAME_RE",
    "_classify_pdb",
    "_classify_symbols",
    "_default_manifest_path",
    "_safe_int",
    "_valid_session_name",
]
