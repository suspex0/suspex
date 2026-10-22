"""ghidra_shim — stdio<->SSE supervisor for the suspex pyghidra backend.

Structural twin of ``idalib_shim`` with one key difference: a single
shared backend process hosts the whole Ghidra project (one JVM, N
programs), so ``SESSIONS`` here maps session ids to *program names*
inside the project rather than to per-binary backend processes.

Spawned by ``suspex.ghidra_bridge`` as ``python ghidra_stdio_shim.py``.
"""
from __future__ import annotations
