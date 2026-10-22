#!/usr/bin/env python
"""LLM-free MCP smoke test: lists tools and runs a scripted recon sequence
against a running suspex-server. Safe by default: without --target nothing
that touches the target executes (status/findings/ida-list only)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# committed catalog written by orchestrator/scripts/gen_tool_catalog.py
CATALOG_PATH = (Path(__file__).resolve().parents[1]
                / "orchestrator/tests/tool_catalog.json")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    ap.add_argument("--target", action="store_true",
                    help="also call target_manage(status) — requires a live agent")
    args = ap.parse_args()

    try:
        from fastmcp import Client
        from fastmcp.exceptions import ToolError
    except ImportError:
        print("fastmcp not installed; run `uv sync` in orchestrator/", file=sys.stderr)
        return 2

    try:
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except OSError:
        print(f"tool catalog not found at {CATALOG_PATH}; run "
              "`uv run python scripts/gen_tool_catalog.py` in orchestrator/",
              file=sys.stderr)
        return 2
    expected = {t["tool"] for t in catalog["tools"] if not t["alias_of"]}
    aliases = sorted(t["tool"] for t in catalog["tools"] if t["alias_of"])

    failures: list[str] = []

    async with Client(args.url) as client:
        tools = await client.list_tools()
        names = sorted(t.name for t in tools)
        print("tools:", ", ".join(names))
        missing = expected - set(names)
        if missing:
            failures.append(f"missing tools: {missing}")
        if aliases:
            print("deprecated aliases (forwarded, not required):",
                  ", ".join(aliases))

        async def call(tool: str, args: dict) -> dict:
            # isError results arrive as a raised ToolError whose message is
            # the canonical envelope JSON — parse it back so negative probes
            # (removed actions, etc.) still see {ok, kind, error, ...}.
            try:
                res = await client.call_tool(tool, args)
            except ToolError as exc:
                try:
                    return json.loads(str(exc))
                except json.JSONDecodeError:
                    return {"ok": False, "error": str(exc)}
            structured = getattr(res, "structured_content", None)
            if isinstance(structured, dict):
                return structured
            text = res.content[0].text if res.content else "{}"
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}

        # findings roundtrip (local-only)
        rec = await call("findings_manage", {
            "action": "record", "severity": "info",
            "title": "smoke test finding", "description": "recorded by smoke_mcp.py",
        })
        print("record:", rec)
        if not rec.get("ok"):
            failures.append(f"findings record failed: {rec}")
        else:
            fid = (rec.get("data") or {}).get("finding_id") or rec.get("finding_id")
            srch = await call("findings_manage", {"action": "search",
                                                  "q": "smoke test finding"})
            print("search:", json.dumps(srch)[:200])
            if not srch.get("ok"):
                failures.append(f"search failed: {srch}")
            upd = await call("findings_manage", {"action": "update",
                                                 "finding_id": fid,
                                                 "status": "closed"})
            print("update:", json.dumps(upd)[:200])
            if not upd.get("ok"):
                failures.append(f"update failed: {upd}")

        # target-independent tools
        ida_list = await call("ida_manage", {"action": "list"})
        print("ida list:", json.dumps(ida_list)[:200])

        if args.target:
            status = await call("target_manage", {"action": "status"})
            print("target status:", json.dumps(status)[:400])
            if not status.get("ok"):
                failures.append(f"target status failed: {status.get('error')}")
            log = await call("exec_manage", {"action": "run_cmd", "command": "echo suspex-smoke"})
            print("exec:", json.dumps(log)[:200])

    if failures:
        print("\nSMOKE FAILED:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nSMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
