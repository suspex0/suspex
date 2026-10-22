"""Envelope contract tests for the v0.14 unified MCP response shape.

Covers the pieces that don't need a live target:
  * envelope_ok / envelope_err builder shapes
  * envelope_from_result coercing legacy tool returns
  * _guard / _guard_pure wrapping every response into the envelope
  * kind resolution across shared shapes (mem_rw.read / debug_manage.read /
    emulate_manage.mem_read all -> kind="read")
  * finalize populates summary.size_bytes
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from suspex.mcp._envelope import (
    EnvelopeOpts,
    KIND_OVERRIDES,
    PageOpts,
    envelope_err,
    envelope_from_result,
    envelope_ok,
    finalize,
    resolve_kind,
)
from suspex.mcp import tools as tools_mod


def _out_env(out):
    """v0.17 A-1: ``_guard`` / ``_guard_pure`` now hand FastMCP a
    ``ToolResult`` whose ``structured_content`` is the envelope, so
    tests that used to ``json.loads(out)`` unwrap through here.
    Legacy JSON strings (fallback path when fastmcp is unavailable)
    also parse cleanly."""
    if isinstance(out, str):
        return json.loads(out)
    sc = getattr(out, "structured_content", None)
    if sc is not None:
        return sc
    raise AssertionError(
        f"cannot extract envelope from {type(out).__name__}: {out!r}"
    )


# ---------------------------------------------------------------------------
# Builder-shape tests
# ---------------------------------------------------------------------------

def test_envelope_ok_minimum_keys():
    env = envelope_ok({"foo": 1}, kind="meta", tool="t", action="a")
    assert env["ok"] is True
    assert env["kind"] == "meta"
    assert env["tool"] == "t"
    assert env["action"] == "a"
    assert env["data"] == {"foo": 1}
    # No summary since no counters were passed.
    assert "summary" not in env
    # `error` MUST be absent on success (not `None`).
    assert "error" not in env


def test_envelope_ok_summary_populated_when_counters_given():
    env = envelope_ok(
        [1, 2, 3], kind="list", tool="t", action="a",
        item_count=3, item_total=100, truncated=True,
        next_cursor="c1", elapsed_ms=42,
    )
    s = env["summary"]
    assert s["item_count"] == 3
    assert s["item_total"] == 100
    assert s["truncated"] is True
    assert s["next_cursor"] == "c1"
    assert s["elapsed_ms"] == 42


def test_envelope_err_nests_error_and_classifies():
    env = envelope_err(
        "AttachProcess failed errno_code=1",
        tool="debug_manage", action="attach",
    )
    assert env["ok"] is False
    assert env["kind"] == "error"
    assert env["tool"] == "debug_manage"
    assert env["action"] == "attach"
    # Hard cutover: error is a nested dict, not flat.
    assert isinstance(env["error"], dict)
    assert "error" in env["error"]
    # _error_enrich should classify this to attach_denied and add a hint.
    assert env["error"]["kind"] == "attach_denied"
    assert "hint" in env["error"]


def test_envelope_err_preserves_partial_data_via_extra():
    env = envelope_err(
        "read failed at offset 0x100",
        tool="mem_rw", action="read",
        extra={"bytes_hex": "aabb", "first_bad_offset": 0x100},
    )
    assert env["ok"] is False
    assert env["data"]["bytes_hex"] == "aabb"
    assert env["data"]["first_bad_offset"] == 0x100


# ---------------------------------------------------------------------------
# Legacy-shape coercion tests
# ---------------------------------------------------------------------------

def test_from_result_wraps_plain_success_dict():
    legacy = {"ok": True, "modules": [{"name": "nt"}], "count": 1}
    env = envelope_from_result(legacy, tool="mem_rw", action="modules")
    assert env["ok"] is True
    assert env["kind"] == "modules"
    assert env["data"]["modules"] == [{"name": "nt"}]
    assert env["data"]["count"] == 1
    # `ok: true` from the legacy dict is dropped (envelope carries it).
    assert "ok" not in env["data"]


def test_from_result_coerces_legacy_flat_error():
    legacy = {"ok": False, "error": "no target", "kind": "no_target",
              "hint": "connect first"}
    env = envelope_from_result(legacy, tool="mem_rw", action="read")
    assert env["ok"] is False
    assert env["kind"] == "error"
    assert env["error"]["error"] == "no target"
    # The explicit kind survives even when the classifier would have flagged it.
    assert env["error"]["kind"] == "no_target"
    assert env["error"]["hint"] == "connect first"


def test_from_result_caller_kind_wins_over_classifier():
    """Regression: `_require_driver` and inline preflights emit an explicit
    kind (e.g. "no_target") alongside a raw string that the regex classifier
    matches to a DIFFERENT slug. The caller's contract is stronger than the
    guess — envelope_from_result must always prefer the caller's kind."""
    # A message the classifier would tag as `channel_unavailable`.
    legacy = {
        "ok": False,
        "kind": "no_target",
        "error": "no target connected: UNAVAILABLE channel closed",
        "hint": "run target_manage(action='connect') first",
    }
    env = envelope_from_result(legacy, tool="mem_rw", action="modules")
    # Caller's explicit kind wins, not the classifier's guess.
    assert env["error"]["kind"] == "no_target"
    assert env["error"]["hint"] == "run target_manage(action='connect') first"


def test_from_result_passes_through_already_envelope():
    already = envelope_ok({"foo": 1}, kind="meta", tool="t", action="a")
    env = envelope_from_result(already, tool="different", action="different")
    # tool/action set by builder are preserved, not overridden.
    assert env["tool"] == "t"
    assert env["action"] == "a"
    assert env is already


def test_from_result_wraps_non_dict_scalar():
    env = envelope_from_result(42, tool="t", action="a")
    assert env["ok"] is True
    assert env["data"] == 42


# ---------------------------------------------------------------------------
# resolve_kind — shared shapes get a canonical kind
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool,action,expected_kind", [
    ("mem_rw",         "read",     "read"),
    ("debug_manage",   "read",     "read"),
    ("emulate_manage", "mem_read", "read"),
    ("mem_rw",         "write",    "write"),
    ("debug_manage",   "regs",     "regs"),
    ("emulate_manage", "regs",     "regs"),
    ("mem_rw",         "disasm",   "disasm"),
    ("debug_manage",   "stacktrace", "backtrace"),
    # No override -> default to action name.
    ("mem_rw",         "modules",  "modules"),
    ("mem_rw",         "handles",  "handles"),
    ("target_manage",  "status",   "status"),
])
def test_resolve_kind(tool, action, expected_kind):
    assert resolve_kind(tool, action) == expected_kind


def test_resolve_kind_explicit_wins():
    assert resolve_kind("mem_rw", "read", explicit="custom") == "custom"


# ---------------------------------------------------------------------------
# finalize — populates summary.size_bytes
# ---------------------------------------------------------------------------

def test_finalize_records_size_bytes():
    env = envelope_ok({"x": "y"}, kind="meta", tool="t", action="a")
    finalize(env, opts=EnvelopeOpts())
    assert "summary" in env
    assert env["summary"]["size_bytes"] > 0
    # Sanity: size roughly matches an actual JSON dump.
    dumped = json.dumps(env)
    assert env["summary"]["size_bytes"] >= len(dumped) - 40  # size was measured before its own key


def test_finalize_raw_verbosity_skips_size():
    env = envelope_ok({"x": "y"}, kind="meta", tool="t", action="a")
    finalize(env, opts=EnvelopeOpts(verbosity="raw"))
    assert env.get("summary") is None or "size_bytes" not in env.get("summary", {})


# ---------------------------------------------------------------------------
# _guard / _guard_pure smoke — every response should be an envelope
# ---------------------------------------------------------------------------

class _FakeSession:
    """Minimal Session double for _guard tests."""

    def __init__(self):
        self.tool_calls: list[tuple[str, str, bool]] = []

    def assert_allowed(self, tool, action, args):  # pragma: no cover - allow-all
        return

    def record_tool_call(self, tool, action, *, args=None, ok=True, error=""):
        self.tool_calls.append((tool, action, ok))


class _FakeCfg:
    """Minimal cfg double — disables auto-spill so envelope tests focus on
    shape, not on the Layer 2 side-effects. test_spill.py exercises the
    spill path in isolation."""

    def spill_dir(self):  # never used because budget = -1
        import pathlib
        return pathlib.Path(".")

    def mcp_max_bytes(self):
        return -1  # disables spill

    def mcp_preview_bytes(self):
        return 512


def _make_ctx():
    return SimpleNamespace(session=_FakeSession(), cfg=_FakeCfg())


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if False else asyncio.new_event_loop().run_until_complete(coro)


def test_guard_wraps_legacy_dict_success():
    ctx = _make_ctx()

    async def fn():
        return {"ok": True, "modules": [1, 2, 3], "count": 3}

    out = _run(tools_mod._guard(ctx, "mem_rw", "modules", {}, fn))
    env = _out_env(out)
    assert env["ok"] is True
    assert env["kind"] == "modules"
    assert env["tool"] == "mem_rw"
    assert env["action"] == "modules"
    assert env["data"]["modules"] == [1, 2, 3]
    assert env["summary"]["size_bytes"] > 0
    assert env["summary"]["elapsed_ms"] >= 0


def test_guard_wraps_legacy_json_string_success():
    ctx = _make_ctx()

    async def fn():
        return json.dumps({"ok": True, "address": "0x1000", "size": 4})

    out = _run(tools_mod._guard(ctx, "mem_rw", "read", {}, fn))
    env = _out_env(out)
    assert env["ok"] is True
    assert env["kind"] == "read"   # KIND_OVERRIDES
    assert env["data"]["address"] == "0x1000"


def test_guard_wraps_legacy_flat_error_string():
    ctx = _make_ctx()

    async def fn():
        # This is what half the inline call sites in tools.py still emit.
        return json.dumps({"ok": False, "kind": "bad_arg",
                           "error": "size is required", "hint": "pass size=..."})

    out = _run(tools_mod._guard(ctx, "mem_rw", "read", {}, fn))
    env = _out_env(out)
    assert env["ok"] is False
    assert env["kind"] == "error"
    assert env["error"]["kind"] == "bad_arg"
    assert env["error"]["hint"] == "pass size=..."


def test_guard_exception_becomes_envelope_err():
    ctx = _make_ctx()

    async def fn():
        raise ValueError("boom")

    out = _run(tools_mod._guard(ctx, "mem_rw", "read", {}, fn))
    env = _out_env(out)
    assert env["ok"] is False
    assert env["kind"] == "error"
    assert "boom" in env["error"]["error"]
    # Session should have recorded the failure.
    assert ctx.session.tool_calls[-1] == ("mem_rw", "read", False)


def test_guard_pure_wraps_success():
    ctx = _make_ctx()

    async def fn():
        return {"encoded_value": "0x2a"}

    out = _run(tools_mod._guard_pure(ctx, "type_convert", "err_lookup", {}, fn))
    env = _out_env(out)
    assert env["ok"] is True
    assert env["kind"] == "err_lookup"
    assert env["data"]["encoded_value"] == "0x2a"


def test_guard_pure_conversion_error_preserves_hint():
    from suspex.mcp.conversions import ConversionError

    ctx = _make_ctx()

    async def fn():
        raise ConversionError("bad_hex", "bad hex", hint="strip prefixes")

    out = _run(tools_mod._guard_pure(ctx, "type_convert", "decode", {}, fn))
    env = _out_env(out)
    assert env["ok"] is False
    assert env["error"]["kind"] == "bad_hex"
    assert env["error"]["hint"] == "strip prefixes"


# ---------------------------------------------------------------------------
# PageOpts smoke
# ---------------------------------------------------------------------------

def test_page_opts_defaults():
    p = PageOpts()
    assert p.limit == 0
    assert p.offset == 0
    assert p.cursor == ""
    assert p.verbosity == "normal"
    e = p.as_envelope_opts()
    assert isinstance(e, EnvelopeOpts)
    assert e.verbosity == "normal"


# ---------------------------------------------------------------------------
# Layer 4 — compact defaults
# ---------------------------------------------------------------------------

def _env_with(data):
    return envelope_ok(data, kind="test", tool="t", action="a")


def test_finalize_strips_int_mirrors_at_normal():
    env = _env_with({"base": "0x1000", "base_int": 4096,
                     "size": "0x40", "size_int": 64})
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["data"] == {"base": "0x1000", "size": "0x40"}


def test_finalize_keeps_int_mirrors_at_full():
    env = _env_with({"base": "0x1000", "base_int": 4096})
    finalize(env, opts=EnvelopeOpts(verbosity="full"))
    assert env["data"] == {"base": "0x1000", "base_int": 4096}


def test_finalize_keeps_int_mirrors_when_include_int():
    env = _env_with({"base": "0x1000", "base_int": 4096})
    finalize(env, opts=EnvelopeOpts(verbosity="normal", include_int=True))
    assert env["data"] == {"base": "0x1000", "base_int": 4096}


def test_finalize_strips_decoded_at_compact():
    env = _env_with({"protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"})
    finalize(env, opts=EnvelopeOpts(verbosity="compact"))
    assert env["data"] == {"protect": "0x20"}


def test_finalize_strips_decoded_at_normal():
    # v0.31: `_decoded` enum siblings are dropped at the default "normal"
    # (they doubled every enum field); the raw value stays.
    env = _env_with({"protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"})
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["data"] == {"protect": "0x20"}


def test_finalize_keeps_decoded_at_full():
    env = _env_with({"protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"})
    finalize(env, opts=EnvelopeOpts(verbosity="full"))
    assert env["data"]["protect_decoded"] == "PAGE_EXECUTE_READ"


def test_finalize_keeps_decoded_when_include_decoded():
    env = _env_with({"protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"})
    finalize(env, opts=EnvelopeOpts(verbosity="normal", include_decoded=True))
    assert env["data"]["protect_decoded"] == "PAGE_EXECUTE_READ"


def test_finalize_collapses_flag_wrappers_at_normal():
    env = _env_with({
        "hvci": {"value": True, "source": "wsc"},
        "cores": 8,
        "products": [
            {"name": "Defender", "enabled": {"value": True, "source": "wsc"}},
        ],
    })
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["data"]["hvci"] is True
    assert env["data"]["cores"] == 8
    assert env["data"]["products"][0]["enabled"] is True


def test_finalize_keeps_flag_wrappers_at_full():
    env = _env_with({"hvci": {"value": True, "source": "wsc"}})
    finalize(env, opts=EnvelopeOpts(verbosity="full"))
    assert env["data"]["hvci"] == {"value": True, "source": "wsc"}


def test_finalize_recurses_into_lists_and_nested_dicts():
    env = _env_with({
        "modules": [
            {"name": "nt", "base": "0xfffff8000", "base_int": 0xfffff8000,
             "protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"},
            {"name": "ntdll", "base": "0x7ffe0000", "base_int": 0x7ffe0000,
             "protect": "0x20", "protect_decoded": "PAGE_EXECUTE_READ"},
        ],
    })
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    for m in env["data"]["modules"]:
        assert "base_int" not in m
        assert "protect_decoded" not in m  # v0.31: normal strips decoded
        assert m["protect"] == "0x20"      # raw value stays


def test_finalize_stripping_leaves_orphan_mirrors_alone():
    # A `_int` key without a bare sibling stays — it might be intentional.
    env = _env_with({"delta_int": 42})
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["data"] == {"delta_int": 42}


def test_finalize_flag_wrapper_only_when_keys_match():
    # {value, source, extra} — `extra` isn't in the allow-list, so keep dict.
    env = _env_with({"posture": {"value": True, "source": "wsc", "extra": 1}})
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["data"]["posture"] == {"value": True, "source": "wsc", "extra": 1}
