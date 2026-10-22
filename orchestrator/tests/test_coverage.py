"""Coverage-block tests (rea-adoption Part 1).

Covers:
- the `_coverage` builder shape + whitelist (unknown scope -> ValueError);
- empty scan with status="unknown" renders limits and is distinguishable
  from a complete empty enumeration;
- paging (summary.truncated) and coverage.status are independent;
- every scope string used by the producer modules is in the approved
  list;
- merge() semantics (weakest status wins, limits concatenate).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from suspex.mcp import _coverage
from suspex.mcp._coverage import APPROVED_SCOPES, attach, coverage, merge
from suspex.mcp._envelope import envelope_ok


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def test_coverage_block_shape() -> None:
    block = coverage("mem-read", "partial", "read_failed_mid_buffer")
    assert block == {"scope": "mem-read", "status": "partial",
                     "limits": ["read_failed_mid_buffer"]}
    assert coverage("enumeration", "complete")["limits"] == []


def test_unknown_scope_rejected() -> None:
    with pytest.raises(ValueError):
        coverage("made-up-scope", "complete")
    with pytest.raises(ValueError):
        coverage("mem-read", "kinda-done")


def test_all_approved_scopes_buildable() -> None:
    for scope in APPROVED_SCOPES:
        assert coverage(scope, "unknown")["scope"] == scope


# ---------------------------------------------------------------------------
# Empty + unknown vs empty + complete
# ---------------------------------------------------------------------------

def test_empty_scan_unknown_vs_complete_enumeration() -> None:
    # "couldn't look": empty scan whose window never got established.
    scan = envelope_ok(
        {"items": [], "hits": 0}, kind="pattern_scan",
        tool="mem_rw", action="pattern_scan",
        coverage=coverage("scan-window", "unknown"),
    )
    # "looked, nothing there": empty enumeration over a proven-complete
    # listing.
    enum = envelope_ok(
        {"items": []}, kind="modules", tool="mem_rw", action="modules",
        coverage=coverage("enumeration", "complete"),
    )
    assert scan["coverage"] == {"scope": "scan-window",
                                "status": "unknown", "limits": []}
    assert enum["coverage"]["status"] == "complete"
    assert scan["coverage"]["status"] != enum["coverage"]["status"]


def test_unknown_with_limits_renders_the_reasons() -> None:
    block = coverage("scan-window", "partial", "scan_limit_reached",
                     "range_unreadable")
    env = envelope_ok({"items": []}, kind="pattern_scan",
                      tool="mem_rw", action="pattern_scan",
                      coverage=block)
    rendered = json.dumps(env)
    assert "scan_limit_reached" in rendered
    assert "range_unreadable" in rendered


# ---------------------------------------------------------------------------
# Paging is independent of coverage
# ---------------------------------------------------------------------------

def test_paging_and_coverage_are_independent() -> None:
    env = envelope_ok(
        {"items": [{"i": i} for i in range(64)]},
        kind="modules", tool="mem_rw", action="modules",
        item_count=64, item_total=200, truncated=True,
        next_cursor="offset:64",
        coverage=coverage("enumeration", "complete"),
    )
    # A fully covered enumeration that is merely paged stays complete...
    assert env["coverage"]["status"] == "complete"
    # ...while the paging contract still reports the truncation.
    assert env["summary"]["truncated"] is True
    assert env["summary"]["next_cursor"] == "offset:64"


# ---------------------------------------------------------------------------
# Every scope string used by producers is approved
# ---------------------------------------------------------------------------

_PRODUCER_FILES = (
    "mem.py", "bin.py", "ida.py", "ghidra.py", "dump.py", "bp.py",
)


def test_producer_scope_strings_are_approved() -> None:
    src_dir = Path(__file__).resolve().parents[1] / "src" / "suspex" / "mcp"
    used: dict[str, list[str]] = {}
    pat = re.compile(r"""coverage\(["']([a-z][a-z-]*)["']""")
    for name in _PRODUCER_FILES:
        text = (src_dir / "tools" / name).read_text(encoding="utf-8")
        for m in pat.finditer(text):
            used.setdefault(m.group(1), []).append(name)
    assert used, "scanner found no coverage() calls — check the regex"
    foreign = sorted(set(used) - set(APPROVED_SCOPES))
    assert not foreign, f"unapproved coverage scopes in producers: {foreign}"


# ---------------------------------------------------------------------------
# merge / attach helpers
# ---------------------------------------------------------------------------

def test_merge_weakest_status_wins_and_limits_concat() -> None:
    merged = merge(coverage("scan-window", "complete"),
                   coverage("scan-window", "partial", "range_unreadable"),
                   coverage("scan-window", "unknown"))
    assert merged["status"] == "unknown"
    assert merged["limits"] == ["range_unreadable"]
    assert merged["scope"] == "scan-window"


def test_merge_scope_mismatch_rejected() -> None:
    with pytest.raises(ValueError):
        merge(coverage("mem-read", "complete"),
              coverage("enumeration", "complete"))


def test_attach_skips_error_envelopes_and_json_round_trips() -> None:
    block = coverage("mem-read", "complete")
    legacy = {"ok": True, "count": 0}
    assert attach(legacy, block) is legacy
    assert legacy["coverage"] == block
    err = {"ok": False, "error": "boom"}
    assert attach(err, block) is err
    assert "coverage" not in err
    as_str = json.dumps(legacy)
    out = attach(as_str, block)
    assert isinstance(out, str)
    assert json.loads(out)["coverage"]["scope"] == "mem-read"
    # Already-covered payloads are untouched.
    assert attach(json.dumps(legacy), block) == json.dumps(legacy)
