"""v0.17 A-1: single-encode MCP tool responses via ``ToolResult``.

Before A-1 every tool return went through ``_j = json.dumps(env, ...)`` and
FastMCP wrapped that JSON string as BOTH ``content[0].text`` and
``structuredContent.result`` — the same payload on the wire twice.

A-1 hands FastMCP a ``ToolResult`` with ``content=[]`` and
``structured_content=<envelope>`` so the envelope reaches the client once,
under ``structuredContent``. ``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` keeps the
old dual-emit shape for one release.

Coverage:

  * :func:`to_tool_result` default emits ``content=[]`` + native
    ``structured_content``.
  * ``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` env flag emits BOTH.
  * ``env['ok'] is False`` maps to ``is_error=True``.
  * Non-dict / non-envelope input falls back to the JSON string.
  * ``_j`` in ``tools.py`` routes finalized envelopes through
    :func:`to_tool_result` and leaves ledger-style (no ``ok`` key)
    dicts / lists on the historical JSON-string path.
  * ``_emit`` (the ``_guard`` finalize seam) produces a ``ToolResult``.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from suspex.mcp import tools as tools_mod
from suspex.mcp._envelope import (
    EnvelopeOpts,
    envelope_ok,
    envelope_err,
    finalize,
    to_tool_result,
)


try:
    from fastmcp.tools.base import ToolResult as _ToolResult
    from mcp.types import TextContent as _TextContent
    _HAS_FASTMCP = True
except Exception:  # pragma: no cover
    _ToolResult = None  # type: ignore[assignment]
    _TextContent = None  # type: ignore[assignment]
    _HAS_FASTMCP = False


pytestmark = pytest.mark.skipif(
    not _HAS_FASTMCP,
    reason="fastmcp not installed — single-encode path requires ToolResult",
)


# ---------------------------------------------------------------------------
# to_tool_result — direct
# ---------------------------------------------------------------------------

def _finalized_env(data=None, *, ok: bool = True, kind: str = "meta") -> dict:
    env = envelope_ok(data or {"foo": 1}, kind=kind, tool="t", action="a") \
        if ok else envelope_err("boom", tool="t", action="a")
    finalize(env, opts=EnvelopeOpts())
    return env


def test_slim_default_no_text_content():
    """Default path: ``content=[]``, envelope lives in ``structured_content``."""
    env = _finalized_env()
    r = to_tool_result(env)
    assert isinstance(r, _ToolResult)
    assert r.content == []
    assert r.structured_content is not None
    assert r.structured_content["ok"] is True
    assert r.structured_content["kind"] == "meta"
    assert r.structured_content["tool"] == "t"
    assert r.is_error is False


def test_slim_error_isError_true():
    """``env['ok'] is False`` MUST map to ``is_error=True``."""
    env = _finalized_env(ok=False)
    assert env["ok"] is False
    r = to_tool_result(env)
    assert isinstance(r, _ToolResult)
    assert r.is_error is True
    assert r.structured_content["ok"] is False
    assert r.structured_content["error"]["kind"]  # some kind classified


def test_slim_legacy_env_flag(monkeypatch):
    """``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` restores the dual-emit shape."""
    monkeypatch.setenv("SUSPX_MCP_LEGACY_DUAL_CONTENT", "1")
    env = _finalized_env()
    r = to_tool_result(env)
    assert isinstance(r, _ToolResult)
    # Legacy path populates BOTH content and structured_content.
    assert len(r.content) == 1
    assert isinstance(r.content[0], _TextContent)
    # Text is the JSON-serialized envelope.
    parsed = json.loads(r.content[0].text)
    assert parsed["ok"] is True
    assert parsed["kind"] == "meta"
    # structured_content also carries the envelope (as a dict).
    assert r.structured_content["ok"] is True


def test_slim_legacy_env_flag_explicit_kwarg():
    """The ``legacy_dual=True`` kwarg wins even when the env is unset."""
    env = _finalized_env()
    r = to_tool_result(env, legacy_dual=True)
    assert len(r.content) == 1
    assert r.structured_content["ok"] is True


def test_slim_env_flag_ignored_when_not_exactly_one(monkeypatch):
    """Only ``=1`` triggers legacy mode. ``true``, ``yes``, ``on`` don't."""
    for val in ("true", "yes", "on", "2", "0", ""):
        monkeypatch.setenv("SUSPX_MCP_LEGACY_DUAL_CONTENT", val)
        r = to_tool_result(_finalized_env())
        assert r.content == [], f"unexpected legacy mode for value {val!r}"


def test_slim_non_dict_falls_back_to_json_string():
    """Defensive: a caller that passes a list / scalar should NOT crash."""
    out = to_tool_result([1, 2, 3])  # type: ignore[arg-type]
    assert isinstance(out, str)
    assert json.loads(out) == [1, 2, 3]


# ---------------------------------------------------------------------------
# ``_j`` — the wrapper at ``tools.py:113-114``
# ---------------------------------------------------------------------------

def test_j_finalized_envelope_returns_tool_result():
    """A finalized envelope (has ``summary.size_bytes``) routes to ``ToolResult``."""
    env = _finalized_env()
    r = tools_mod._j(env)
    assert isinstance(r, _ToolResult)
    assert r.structured_content["ok"] is True


def test_j_pre_finalize_envelope_stays_string():
    """A raw envelope (no ``summary.size_bytes``) MUST stay a JSON string so
    ``_coerce_to_envelope`` in ``_guard`` can still parse and re-wrap it —
    this is how legacy ``run()`` bodies with ``return _j({"ok": ...})`` work.
    """
    raw = {"ok": True, "modules": [1, 2]}
    out = tools_mod._j(raw)
    assert isinstance(out, str)
    assert json.loads(out) == raw


def test_j_ledger_style_dict_stays_string():
    """A ledger-style dict (parity report, arbitrary agent response) has no
    ``ok`` key → stays a JSON string so ``ctx.ledger.add_evidence(content=...)``
    still receives a string."""
    report = {"summary": {"n_regions": 4}, "checks": []}
    out = tools_mod._j(report)
    assert isinstance(out, str)
    assert json.loads(out) == report


def test_j_list_stays_string():
    """``_j(matches)`` — where matches is a list — stays a JSON string
    (yara-match writer at tools.py:3676)."""
    matches = [{"rule": "r1"}, {"rule": "r2"}]
    out = tools_mod._j(matches)
    assert isinstance(out, str)
    assert json.loads(out) == matches


# ---------------------------------------------------------------------------
# ``_emit`` — the finalize/spill seam
# ---------------------------------------------------------------------------

class _FakeCfg:
    def mcp_max_bytes(self):
        return 0

    def spill_dir(self):
        # Never reached because mcp_max_bytes()==0 disables spill.
        return None

    def mcp_preview_bytes(self):
        return 512


class _FakeSession:
    def __init__(self):
        self.tool_calls = []

    def assert_allowed(self, *a, **k):
        pass

    def record_tool_call(self, tool, action, ok=True, error=None, args=None):
        self.tool_calls.append((tool, action, ok))


def _make_ctx():
    return SimpleNamespace(session=_FakeSession(), cfg=_FakeCfg())


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_emit_returns_tool_result_on_success():
    ctx = _make_ctx()
    env = envelope_ok({"foo": 1}, kind="meta", tool="t", action="a")
    out = tools_mod._emit(env, ctx=ctx)
    assert isinstance(out, _ToolResult)
    assert out.content == []
    assert out.structured_content["ok"] is True
    assert out.structured_content["summary"]["size_bytes"] > 0
    assert out.is_error is False


def test_emit_returns_tool_result_on_error():
    ctx = _make_ctx()
    env = envelope_err("boom", tool="t", action="a")
    out = tools_mod._emit(env, ctx=ctx)
    assert isinstance(out, _ToolResult)
    assert out.is_error is True
    assert out.structured_content["ok"] is False


def test_guard_returns_tool_result_end_to_end():
    ctx = _make_ctx()

    async def fn():
        return {"ok": True, "hello": "world"}

    out = _run(tools_mod._guard(ctx, "mem_rw", "modules", {}, fn))
    assert isinstance(out, _ToolResult)
    assert out.content == []
    env = out.structured_content
    assert env["ok"] is True
    assert env["kind"] == "modules"
    assert env["tool"] == "mem_rw"
    assert env["action"] == "modules"
    assert env["data"]["hello"] == "world"


def test_guard_exception_returns_error_tool_result():
    ctx = _make_ctx()

    async def fn():
        raise ValueError("boom")

    out = _run(tools_mod._guard(ctx, "mem_rw", "read", {}, fn))
    assert isinstance(out, _ToolResult)
    assert out.is_error is True
    assert out.structured_content["ok"] is False


def test_emit_legacy_dual_content_env_flag(monkeypatch):
    """End-to-end: with the legacy env set, ``_emit`` dual-emits."""
    monkeypatch.setenv("SUSPX_MCP_LEGACY_DUAL_CONTENT", "1")
    ctx = _make_ctx()
    env = envelope_ok({"foo": 1}, kind="meta", tool="t", action="a")
    out = tools_mod._emit(env, ctx=ctx)
    assert isinstance(out, _ToolResult)
    assert len(out.content) == 1
    assert isinstance(out.content[0], _TextContent)
    # And structured_content is still populated.
    assert out.structured_content["ok"] is True
