---
description: "Start the suspex0 orchestrator and verify the suspex0 MCP endpoint"
---
The suspex0 orchestrator serves the suspex0 MCP server on http://127.0.0.1:8765/mcp.
If it is not running, Kilo's suspex0 MCP toggle fails with an "SSE error: Unable to connect".

Do the following:
1. Run `powershell -ExecutionPolicy Bypass -File scripts\start_orchestrator.ps1` from the repo root
   (it no-ops when the orchestrator is already up; logs to orchestrator\orchestrator-start.log).
2. Verify port 8765 is listening and a streamable-HTTP initialize POST to http://127.0.0.1:8765/mcp returns HTTP 200.
3. Report the result. If healthy, tell me to enable the suspex0 MCP via /mcps.
