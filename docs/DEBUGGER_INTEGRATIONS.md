# Debugger MCP integrations — research notes

References the user flagged as potentially useful. Neither is implemented in
suspex0 v1; both validate the architecture and mark clean extension points.

## mcp-windbg (github.com/svnscha/mcp-windbg)

MCP server wrapping WinDbg/cdb (DbgEng command line). Overlaps heavily with
suspex0's `Debug`/`Breakpoints` gRPC services — suspex0 already implements the
same primitives (attach/launch, sw+hw breakpoints, regs, threads, stacks,
memory R/W, event streaming) natively through IDebugControl/IDebugRegisters,
delivered as manage-style MCP tools instead of a passthrough console.

Useful ideas worth borrowing later:
- command-passthrough tool (run an arbitrary dbgeng command, return text) —
  **already implemented** as `debug_manage(action="cmd", command="…")`; used
  as an escape hatch when a dbgeng command has no first-class MCP verb.
- symbol-path management as an explicit tool action (we handle it via config +
  `_NT_SYMBOL_PATH`).

## x64dbgmcp (github.com/wasdubya/x64dbgmcp)

MCP plugin for x64dbg (user-mode GUI debugger). Complementary rather than
competing: x64dbg covers interactive GUI-driven sessions where the analyst
wants the LLM to react to what they see.

Integration path if wanted later: FastMCP supports aggregating multiple MCP
servers — mount x64dbgmcp alongside suspex0's own tools in `server.py`
(composition, not a port). The suspex0 protocol stays untouched. Guardrails
to keep: the same allowlist/tool-log/destructive-flag treatment must wrap any
third-party debugger tools before they reach the LLM.

## Decision

v1 keeps the native DbgEng implementation (no external debugger MCP
dependency). `debug_manage action="cmd"` passthrough is live;
x64dbg aggregation is still deferred pending demand.
