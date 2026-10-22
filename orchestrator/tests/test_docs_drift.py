"""Docs drift tests: SKILL.md tool count and the README tool-surface
table must agree with the committed tool catalog.

Convention (decided here): the SKILL count and README rows cover REAL
tools only — the deprecated ``findings_manage`` alias does not count
(it is documented inside ``knowledge_manage``'s row instead). So the
count is 19 while the registry lists 20 names.
"""

from __future__ import annotations

import re

import _catalog


def _load_catalog() -> dict:
    return _catalog.load_catalog()


def _real_tool_names(catalog: dict) -> list[str]:
    return [e["tool"] for e in catalog["tools"] if not e["alias_of"]]


def test_skill_md_tool_count_matches_catalog() -> None:
    text = _catalog.SKILL_PATH.read_text(encoding="utf-8")
    # lookbehind keeps the phrase "suspex0 MCP tools" in the frontmatter
    # from matching as count 0
    match = re.search(r"(?<![A-Za-z0-9_*])(\d+)\s+MCP tools", text)
    assert match, "SKILL.md lost its 'N MCP tools' count line"
    assert int(match.group(1)) == len(_real_tool_names(_load_catalog())), (
        f"SKILL.md says {match.group(1)} MCP tools but the catalog has "
        f"{len(_real_tool_names(_load_catalog()))} real tools; update the "
        "count when the tool surface changes"
    )


def test_readme_tool_table_matches_generated_block() -> None:
    text = _catalog.README_PATH.read_text(encoding="utf-8")
    start = text.index(_catalog.README_TABLE_START)
    end = text.index(_catalog.README_TABLE_END) + len(_catalog.README_TABLE_END)
    assert text[start:end] == _catalog.readme_full_block(_load_catalog()), (
        "README tool table drifted; run "
        "`uv run python scripts/gen_tool_catalog.py` and commit the result"
    )


def test_readme_table_covers_every_real_tool() -> None:
    text = _catalog.README_PATH.read_text(encoding="utf-8")
    for name in _real_tool_names(_load_catalog()):
        assert f"`{name}`" in text, f"README never mentions tool {name}"
