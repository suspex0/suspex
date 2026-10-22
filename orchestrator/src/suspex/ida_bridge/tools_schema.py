"""Tools/schema mixin: tools/list caching, raw and text-shaped tool calls."""

from __future__ import annotations

import json
import logging
from typing import Any

from .errors import IdaBridgeError

log = logging.getLogger(__name__)


class IdaToolsMixin:
    """MCP tool inventory + call helpers used across the bridge."""

    async def list_tools(self) -> list[dict[str, Any]]:
        await self.ensure_started()
        return list(self._tools.values())

    async def refresh_tools(self) -> bool:
        """Re-fetch tools/list from the shim.

        The startup inventory registers generic schemas; the shim only
        learns real per-tool argument shapes after the first backend
        session comes up, so schema-consuming callers need this refresh.
        Returns True when the shim answered and the cache was replaced.
        """
        await self.ensure_started()
        try:
            result = await self._call("tools/list", {}, timeout=30)
        except IdaBridgeError:
            return False
        # replace, don't merge -- name set may have shrunk too
        self._tools = {t["name"]: t for t in result.get("tools", [])}
        return True

    async def _refresh_tools_for_live_backend(self) -> None:
        """v0.24: one-shot inventory refresh once a live backend exists.

        The startup tools/list runs before any backend is spawned, so
        the extension tools registered inside the backend process
        (exec_idapython, pattern_scan, ...) are absent from
        ``self._tools`` until the shim caches real per-tool schemas off
        a live session. Call this wherever a session becomes known-live;
        the flag latches once the refreshed inventory carries a real
        (non-generic) schema — a refresh that still shows the generic
        placeholder set means backend meta hasn't landed yet, so the
        next session-live point retries.
        """
        if self._tools_live_refreshed:
            return
        try:
            ok = await self.refresh_tools()
        except Exception:  # noqa: BLE001 - best-effort; never break an open
            return
        if not ok:
            return
        generic = {"type": "object", "additionalProperties": True}
        if any((t.get("inputSchema") or {}) != generic
               for t in self._tools.values()):
            self._tools_live_refreshed = True

    async def call_tool_raw(self, name: str, arguments: dict[str, Any]) -> Any:
        await self.ensure_started()
        result = await self._call(
            "tools/call", {"name": name, "arguments": arguments}, timeout=self.cfg.open_timeout_s
        )
        if name == "tools/list":
            for t in result.get("tools", []):
                self._tools[t["name"]] = t
        return result

    @staticmethod
    def _result_text(result: Any) -> str:
        if not isinstance(result, dict):
            return str(result)
        content = result.get("content", [])
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return "\n".join(parts) if parts else json.dumps(result)[:4000]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        result = await self.call_tool_raw(name, arguments)
        if result.get("isError"):
            text = self._result_text(result)
            return "ERROR: " + text + self._schema_hint(name, text)
        return self._result_text(result)

    def _schema_hint(self, name: str, text: str) -> str:
        """v0.24: append the tool's real inputSchema to validation errors
        so an arg-name mismatch (address vs memory_address vs
        function_address) is corrected on the retry instead of costing a
        schemas round-trip per mistake."""
        low = text.lower()
        if not any(k in low for k in ("validation", "unexpected", "missing",
                                      "required", "argument", "field",
                                      "unexpected keyword")):
            return ""
        tool = self._tools.get(name) or {}
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        if not props:
            return ""
        def _shape(v: Any) -> str:
            if not isinstance(v, dict):
                return "?"
            if "type" in v:
                return str(v["type"])
            if "anyOf" in v:
                alts = [str(a.get("type", "?"))
                        for a in v["anyOf"] if isinstance(a, dict)]
                return "|".join(alts) or "?"
            return "?"
        parts = [f"{k}: {_shape(v)}" for k, v in sorted(props.items())]
        hint = f"\nexpected args for {name}: " + "; ".join(parts)
        req = schema.get("required") or []
        if req:
            hint += f" | required: {', '.join(sorted(req))}"
        return hint

    def _require_tool(self, name: str) -> None:
        if self._tools and name not in self._tools:
            raise IdaBridgeError(
                f"ida_bridge: tool '{name}' not offered by idalib-mcp. Available: "
                + ", ".join(sorted(self._tools))
            )

    def tool_schemas(self) -> list[dict[str, Any]]:
        """Full tool inventory with inputSchema. Callers use this to look
        up argument shape (offset/count, address, function_name, ...) for
        the ida_manage passthrough."""
        return sorted(self._tools.values(), key=lambda t: t.get("name", ""))
