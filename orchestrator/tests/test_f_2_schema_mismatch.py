"""v0.17 F-2 — pydantic schema-mismatch intercepts + tool-name substitution
+ KNOWN_KINDS registry lint.

Kwarg drift used to bubble raw pydantic text (``1 validation error for
FooArgs -> extra_forbidden``). The new HINT_RULES entries classify these
as ``schema_mismatch`` / ``schema_missing_field`` and the enrich_error
pipeline substitutes the calling tool's name into the hint so callers see
``schemas(tools=['mem_rw'])`` instead of the ``<this_tool>`` placeholder.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from suspex.mcp._error_enrich import classify, enrich_error
from suspex.mcp.error_maps import KNOWN_KINDS, is_known_kind


# --------------------------------------------------------------------------- #
# F-2a — schema_mismatch / schema_missing_field classifier
# --------------------------------------------------------------------------- #


def test_f_2_extra_forbidden_classifies_schema_mismatch():
    """The canonical pydantic v2 wall of text for an unknown kwarg."""
    msg = (
        "1 validation error for MemRwArgs\n"
        "bogus_kwarg\n"
        "  Extra inputs are not permitted [type=extra_forbidden, "
        "input_value='oops', input_type=str]"
    )
    kind, hint = classify(msg)
    assert kind == "schema_mismatch"
    assert "schemas(" in hint


def test_f_2_missing_field_classifies_schema_missing_field():
    """Pydantic v2 wording when a required field is absent."""
    msg = (
        "1 validation error for MemRwArgs\n"
        "address\n"
        "  Field required [type=missing, input_value={}, input_type=dict]"
    )
    kind, hint = classify(msg)
    assert kind == "schema_missing_field"
    assert "schemas(" in hint or "required" in hint


# --------------------------------------------------------------------------- #
# F-2a — <this_tool> substitution
# --------------------------------------------------------------------------- #


def test_f_2_hint_substitutes_tool_name():
    """The <this_tool> placeholder is replaced when a tool is supplied."""
    msg = "1 validation error for MemRwArgs\nfoo\n  Extra inputs are not permitted"
    kind, hint = classify(msg, tool="mem_rw")
    assert kind == "schema_mismatch"
    assert "<this_tool>" not in hint
    assert "mem_rw" in hint


def test_f_2_hint_leaves_placeholder_when_no_tool_provided():
    """No tool -> no substitution; the sentinel survives verbatim."""
    msg = "1 validation error for FooArgs\nx\n  Extra inputs are not permitted"
    kind, hint = classify(msg)
    assert kind == "schema_mismatch"
    # Without a tool we leave the placeholder in place — callers still see
    # the pointer to schemas(...), just not with a name filled in.
    assert "<this_tool>" in hint or "schemas(" in hint


def test_f_2_enrich_error_full_pipeline_substitutes_tool():
    """enrich_error passes the tool name through to classify()."""
    msg = "1 validation error for FooArgs\nx\n  Extra inputs are not permitted"
    out = enrich_error("ida_manage", "open", msg)
    assert out["kind"] == "schema_mismatch"
    assert "ida_manage" in out.get("hint", "")


# --------------------------------------------------------------------------- #
# F-2b — KNOWN_KINDS registry lint
# --------------------------------------------------------------------------- #


def test_f_2_known_kinds_registry_covers_tools_py():
    """Every dict-literal ``kind`` in the tools package is documented in KNOWN_KINDS.

    A drift-guard: a typo like ``"kind": "bad_argment"`` would pass a
    smoke run but silently break any caller branching on the slug. The
    fix is always to correct the typo in the tool code — NEVER to relax
    the registry.

    v0.18: ``mcp/tools.py`` split into ``mcp/tools/*.py`` — walk every
    module in the package and concatenate their sources.
    """
    tools_pkg = Path(__file__).resolve().parents[1].joinpath(
        "src", "suspex", "mcp", "tools")
    tools_src = "\n".join(
        f.read_text(encoding="utf-8") for f in sorted(tools_pkg.rglob("*.py"))
    )
    used = set(re.findall(r'[\'"]kind[\'"]\s*:\s*[\'"]([a-z_][a-z_0-9]*)[\'"]',
                          tools_src))
    unregistered = used - KNOWN_KINDS
    assert not unregistered, (
        f"Undocumented kind slug(s) in tools package — register in "
        f"error_maps.KNOWN_KINDS or fix the typo: {sorted(unregistered)}"
    )


def test_f_2_known_kinds_covers_hint_rules():
    """Every ``kind`` in HINT_RULES is documented in KNOWN_KINDS."""
    from suspex.mcp._error_enrich import HINT_RULES
    rule_kinds = {kind for _, kind, _ in HINT_RULES}
    unregistered = rule_kinds - KNOWN_KINDS
    assert not unregistered, (
        f"HINT_RULES emits kind(s) not in KNOWN_KINDS: "
        f"{sorted(unregistered)}"
    )


def test_f_2_is_known_kind_helper():
    assert is_known_kind("partial_read") is True
    assert is_known_kind("schema_mismatch") is True
    assert is_known_kind("this_is_not_registered") is False


def test_f_2_reserved_slugs_land_in_registry():
    """§0.4 reserves these v0.17 slugs across every worker — verify they
    all landed in the registry F ships."""
    reserved = {
        # F's own
        "connect_blocked", "connect_timeout", "connect_refused",
        "host_unreachable", "network_unreachable",
        "wait_timeout",
        "schema_mismatch", "schema_missing_field",
        "pte_absent", "kuser_readable", "vad_probed",
        # Other workers rely on F's registry to accept their slugs
        "unknown_kwarg", "kwarg_collision", "filter_no_match",
        "foreign_owned", "watchdog_collision",
        "session_exists",
        "stale_kaslr", "no_module_at_va",
        "pdb_layout_missing",
    }
    missing = reserved - KNOWN_KINDS
    assert not missing, f"Reserved slug(s) not in KNOWN_KINDS: {sorted(missing)}"
