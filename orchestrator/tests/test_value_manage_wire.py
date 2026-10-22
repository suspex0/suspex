"""v0.17.1 — end-to-end wire shape for the value_manage MCP tool.

Covers the shape a caller sees on the wire once value_ops.dispatch has
returned and the envelope layer has coerced the legacy result dict into
the v0.14 unified envelope. The dispatch-level and eval-level tests live
in the sibling test_value_manage_* files.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from suspex.mcp import tools as tools_mod
from suspex.mcp import value_ops


class _FakeSession:
    def __init__(self) -> None:
        self.tool_calls: list[tuple[str, str, bool]] = []

    def record_tool_call(self, tool, action, *, args=None, ok=True, error=None):
        self.tool_calls.append((tool, action, ok))


class _FakeCfg:
    def mcp_max_bytes(self):
        return -1

    def mcp_preview_bytes(self):
        return 512

    def spill_dir(self):
        return "."


def _ctx():
    return SimpleNamespace(session=_FakeSession(), cfg=_FakeCfg())


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _env(out) -> dict:
    """v0.17 A-1: ``_guard_pure`` hands FastMCP a ``ToolResult`` whose
    ``structured_content`` is the envelope; legacy string returns
    unwrap via ``json.loads``."""
    if isinstance(out, str):
        return json.loads(out)
    sc = getattr(out, "structured_content", None)
    if sc is not None:
        return sc
    raise AssertionError(
        f"cannot extract envelope from {type(out).__name__}: {out!r}"
    )


# ---------------------------------------------------------------------------
# Surface — value_manage is the single entry point; type_convert is gone.
# ---------------------------------------------------------------------------


class TestSurface:
    def test_action_list_covers_legacy_and_new(self):
        legacy = {"cast", "views", "pack", "unpack", "swap", "split",
                  "join", "bits", "err_lookup", "time", "guid",
                  "encode", "decode", "str_convert", "hash"}
        assert legacy.issubset(set(value_ops.VALUE_MANAGE_ACTIONS))
        assert "eval" in value_ops.VALUE_MANAGE_ACTIONS
        assert "constants" in value_ops.VALUE_MANAGE_ACTIONS


# ---------------------------------------------------------------------------
# End-to-end wire shape for the two new actions.
# ---------------------------------------------------------------------------


class TestEvalWireShape:
    def test_headline_arithmetic(self):
        out = value_ops.dispatch("eval", expr="0x1000 + 0x40*8")
        # 4096 + 512 = 4608 = 0x1200.
        assert out["ok"] is True
        assert out["action"] == "eval"
        assert out["result"] == 0x1200
        assert out["result_hex"] == "0x1200"
        assert out["expression"] == "0x1000 + 0x40*8"

    def test_named_constant(self):
        out = value_ops.dispatch("eval", expr="PAGE_SIZE * 4")
        assert out["result"] == 0x4000

    def test_env_precedence(self):
        # Caller-supplied env shadows the built-in constants table.
        out = value_ops.dispatch(
            "eval", expr="PAGE_SIZE", env={"PAGE_SIZE": 8192})
        assert out["result"] == 8192


class TestConstantsWireShape:
    def test_shape(self):
        out = value_ops.dispatch("constants")
        assert out["ok"] is True
        assert out["action"] == "constants"
        assert out["count"] > 0
        assert any(e["name"] == "PAGE_SIZE" for e in out["constants"])
        page = next(e for e in out["constants"] if e["name"] == "PAGE_SIZE")
        assert page["value_hex"] == "0x1000"

    def test_category_filter(self):
        out = value_ops.dispatch("constants", category="masks")
        assert out["ok"] is True
        assert out["filtered_by"] == "masks"
        assert all(e["category"] == "masks" for e in out["constants"])


# ---------------------------------------------------------------------------
# Envelope integration: warnings lifted from a legacy result dict.
# ---------------------------------------------------------------------------


class TestEnvelopeWarningLift:
    def test_mod_wrap_warning_surfaces(self):
        # eval with mod_wrap=True + overflow returns warnings inside the
        # result dict; envelope_from_result lifts them to the top level.
        ctx = _ctx()

        async def fn():
            return value_ops.dispatch(
                "eval", expr="MAXULONG64 + 1", width=64, mod_wrap=True)

        out = _run(tools_mod._guard_pure(
            ctx, "value_manage", "eval", {"action": "eval"}, fn))
        env = _env(out)
        assert env["ok"] is True
        assert env["tool"] == "value_manage"
        # mod_wrap produces result=0 with a warning.
        assert env["data"]["result"] == 0
        assert env.get("warnings"), \
            "mod_wrap overflow should surface a warning at envelope top level"
        assert "warnings" not in env.get("data", {})
