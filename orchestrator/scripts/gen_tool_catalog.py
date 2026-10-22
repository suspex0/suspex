#!/usr/bin/env python
"""Regenerate ``tests/tool_catalog.json`` + the README tool-surface table.

Usage (from ``orchestrator/``)::

    uv run python scripts/gen_tool_catalog.py

Prints ``wrote N tools, M actions``. The collection logic lives in
``tests/_catalog.py`` (shared with the drift tests — one implementation
only). Re-run and commit whenever the MCP tool surface changes;
``test_tool_catalog.py`` / ``test_docs_drift.py`` fail on drift.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ORCHESTRATOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ORCHESTRATOR_DIR / "tests"))

from _catalog import (  # noqa: E402 — path bootstrap must run first
    CATALOG_PATH,
    README_PATH,
    README_TABLE_END,
    README_TABLE_START,
    build_live_catalog,
    catalog_to_json,
    readme_full_block,
)


def update_readme_table(catalog: dict) -> bool:
    """Replace the marked tool-table region in README.md in place.

    Returns True when the README changed, False when it already matched
    (regeneration is idempotent).
    """
    text = README_PATH.read_text(encoding="utf-8")
    start = text.index(README_TABLE_START)
    end = text.index(README_TABLE_END) + len(README_TABLE_END)
    block = readme_full_block(catalog)
    if text[start:end] == block:
        return False
    README_PATH.write_text(text[:start] + block + text[end:], encoding="utf-8")
    return True


async def main() -> int:
    catalog = await build_live_catalog()
    tools = catalog["tools"]
    n_actions = sum(len(t["actions"] or []) for t in tools)
    CATALOG_PATH.write_text(catalog_to_json(catalog), encoding="utf-8")
    changed = update_readme_table(catalog)
    print(f"wrote {len(tools)} tools, {n_actions} actions"
          + (" (+ regenerated README tool table)" if changed else ""))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
