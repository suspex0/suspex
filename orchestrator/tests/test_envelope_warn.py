"""v0.17 A-5: `warn()` / `warn_if()` helpers on the envelope module.

Every worker that appends to ``env['warnings']`` uses this helper so the
list stays deduped and lazily created. Coverage:

  * :func:`warn` appends and dedupes.
  * :func:`warn_if` is conditional.
  * :func:`warn` ignores empty / falsey messages.
  * :func:`warn` output survives :func:`finalize`.
"""

from __future__ import annotations

from suspex.mcp._envelope import (
    EnvelopeOpts,
    envelope_ok,
    finalize,
    warn,
    warn_if,
)


def _env() -> dict:
    return envelope_ok({"foo": 1}, kind="meta", tool="t", action="a")


def test_warn_appends_and_dedupes():
    env = _env()
    warn(env, "first")
    warn(env, "second")
    warn(env, "first")  # duplicate
    assert env["warnings"] == ["first", "second"]


def test_warn_returns_env_for_chaining():
    env = _env()
    same = warn(env, "hi")
    assert same is env


def test_warn_creates_list_lazily():
    env = _env()
    assert "warnings" not in env
    warn(env, "boom")
    assert env["warnings"] == ["boom"]


def test_warn_ignores_empty_string():
    env = _env()
    warn(env, "")
    warn(env, None)  # type: ignore[arg-type]
    assert "warnings" not in env


def test_warn_stringifies_non_str():
    env = _env()
    warn(env, 42)  # type: ignore[arg-type]
    assert env["warnings"] == ["42"]


def test_warn_if_conditional_true_appends():
    env = _env()
    warn_if(env, True, "yes")
    warn_if(env, False, "no")
    warn_if(env, "", "empty-cond")
    assert env["warnings"] == ["yes"]


def test_warn_if_returns_env_for_chaining():
    env = _env()
    same = warn_if(env, True, "hi")
    assert same is env


def test_warn_survives_finalize_normal():
    env = _env()
    warn(env, "note")
    finalize(env, opts=EnvelopeOpts(verbosity="normal"))
    assert env["warnings"] == ["note"]
    # `finalize` should also add size_bytes without disturbing warnings.
    assert env["summary"]["size_bytes"] > 0


def test_warn_survives_finalize_compact():
    env = _env()
    warn(env, "compact-note")
    finalize(env, opts=EnvelopeOpts(verbosity="compact"))
    assert env["warnings"] == ["compact-note"]


def test_warn_survives_finalize_raw():
    env = _env()
    warn(env, "raw-note")
    finalize(env, opts=EnvelopeOpts(verbosity="raw"))
    assert env["warnings"] == ["raw-note"]
