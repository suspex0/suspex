"""pyghidra_ext — suspex0's headless Ghidra backend package.

Runs inside a plain CPython process (NO IDA dependencies). Boots the JVM
via pyghidra/JPype, owns one shared Ghidra project, and serves an MCP
SSE endpoint whose tool surface mirrors ida-pro-mcp's verbs plus the
suspex extension set (pcode, struct layouts, masked scans,
exec_ghidra_script).

See ``suspex_pyghidra_ext.py`` for the spawn entrypoint and
``ghidra_shim`` for the orchestrator-side supervisor that fronts it.
"""
from __future__ import annotations
