"""Part 4 · completion/complete handler — sources, shaping, safety.

pins:
  * machine/view completion from session + config state, prefix-matched
  * unknown ref/argument -> None (empty, never an error)
  * 100-value cap with total/has_more when truncating
  * dedupe + code-point sort
  * completion is read-only: no ledger rows, no targets, no tool calls
"""

from __future__ import annotations

import types

from suspex.config import MachineConfig, SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.mcp.prompts import completions as C
from suspex.session import Session


def _ctx(tmp_path):
    cfg = SuspexConfig()
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path)
    cfg.machines = {"lab9": MachineConfig(host="127.0.0.1", token="t")}
    session = Session(cfg)
    # two "connected" machines — machines() only reads the clients keys
    session.clients["lab2.kernel"] = object()
    session.clients["lab2.user"] = object()
    session.clients["lab3.kernel"] = object()
    ledger = FindingsLedger(tmp_path / "findings.db")
    return types.SimpleNamespace(cfg=cfg, session=session, ledger=ledger)


def _ref(name="kernel_recon"):
    return types.SimpleNamespace(name=name, type="ref/prompt")


def _arg(name, value=""):
    return types.SimpleNamespace(name=name, value=value)


def _handler(tmp_path):
    return C.make_completion_handler(_ctx(tmp_path))


def _vals(result) -> list[str]:
    if result is None:
        return []
    if isinstance(result, list):
        return list(result)
    return list(result.values)


def _has_more(result):
    return bool(getattr(result, "has_more", None)
                or getattr(result, "hasMore", None))


def _total(result):
    return getattr(result, "total", None)


# --------------------------------------------------------------------------- #


def test_machine_completion_prefix_and_case(tmp_path) -> None:
    h = _handler(tmp_path)
    assert _vals(h(_ref(), _arg("machine", "lab"))) == \
        ["lab2", "lab3", "lab9"]
    assert _vals(h(_ref(), _arg("machine", "lab2"))) == ["lab2"]
    assert _vals(h(_ref(), _arg("machine", "LAB"))) == \
        ["lab2", "lab3", "lab9"]
    assert _vals(h(_ref(), _arg("machine", "zzz"))) == []


def test_view_completion_lists_machine_dot_kind(tmp_path) -> None:
    h = _handler(tmp_path)
    vals = _vals(h(_ref(), _arg("view", "")))
    assert "lab2.kernel" in vals and "lab2.user" in vals
    assert "lab9.kernel" in vals
    # both view kinds are offered for every known machine (spec table),
    # even when only one is connected right now
    assert _vals(h(_ref(), _arg("view", "lab3."))) == \
        ["lab3.kernel", "lab3.user"]


def test_unknown_ref_and_argument_return_none(tmp_path) -> None:
    h = _handler(tmp_path)
    assert h(_ref("not_a_prompt"), _arg("machine", "")) is None
    assert h(_ref(), _arg("color", "")) is None
    assert h(_ref("crash_triage"), _arg("finding_id", "")) is None or \
        _vals(h(_ref("crash_triage"), _arg("finding_id", ""))) == []


def test_finding_ids_capped_at_100_with_total(tmp_path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    rows = [types.SimpleNamespace(id=f"f{i:03d}") for i in range(150)]
    monkeypatch.setattr(ctx.ledger, "list_findings",
                        lambda *a, **k: rows, raising=False)
    h = C.make_completion_handler(ctx)
    out = h(_ref("investigate_finding"), _arg("finding_id", "f"))
    assert isinstance(out, C.Completion)
    assert len(out.values) == 100
    assert _total(out) == 150
    assert _has_more(out) is True
    # rule 1 shaping is deterministic: code-point sort, then cap — so the
    # kept window is f000..f099 even though the source list is
    # most-recent-first (recency governs the source order only)
    assert out.values[0] == "f000"
    assert "f149" not in out.values


def test_finding_ids_prefix_filtered(tmp_path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    rows = [types.SimpleNamespace(id=f"f{i:03d}") for i in range(5)]
    monkeypatch.setattr(ctx.ledger, "list_findings",
                        lambda *a, **k: rows, raising=False)
    h = C.make_completion_handler(ctx)
    assert _vals(h(_ref(), _arg("finding_id", "f00"))) == \
        ["f000", "f001", "f002", "f003", "f004"]


def test_dedupe_and_sort(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    ctx._retained_inventories = {"module": ["b.sys", "a.sys", "a.sys", "B.SYS"]}
    h = C.make_completion_handler(ctx)
    assert _vals(h(_ref(), _arg("module", ""))) == ["a.sys", "b.sys"]
    # case-insensitive prefix, canonical (retained) spelling kept
    assert _vals(h(_ref(), _arg("module", "A"))) == ["a.sys"]


def test_retained_sources_empty_means_no_data_not_absence(tmp_path) -> None:
    """No retained inventory yet -> empty candidates, not an error."""
    h = _handler(tmp_path)
    assert _vals(h(_ref(), _arg("module", ""))) == []
    assert _vals(h(_ref(), _arg("symbol", "Nt"))) == []
    assert _vals(h(_ref(), _arg("device", ""))) == []


def test_ledger_errors_swallow_to_empty(tmp_path) -> None:
    ctx = _ctx(tmp_path)

    def _boom(*a, **k):
        raise RuntimeError("ledger closed")

    ctx.ledger = types.SimpleNamespace(list_findings=_boom,
                                       evidence_for=_boom)
    h = C.make_completion_handler(ctx)
    assert _vals(h(_ref(), _arg("finding_id", ""))) == []
    assert _vals(h(_ref(), _arg("evidence_id", ""))) == []
    assert h(_ref(), _arg("finding_id", "")) is not None  # values, not None-error


def test_completion_has_no_side_effects(tmp_path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    ledger = ctx.ledger
    fid = ledger.list_findings(None, None)
    assert fid == []

    def _count_books():
        return len(ledger.list_findings(None, None))

    h = C.make_completion_handler(ctx)
    session = ctx.session
    before = (len(session.clients), _count_books(),
              len(session.tool_log), len(ledger._conn.execute(
                  "SELECT * FROM evidence").fetchall()))
    for _ in range(5):
        h(_ref(), _arg("machine", "lab"))
        h(_ref(), _arg("view", ""))
        h(_ref(), _arg("finding_id", ""))
        h(_ref(), _arg("evidence_id", ""))
    after = (len(session.clients), _count_books(),
             len(session.tool_log), len(ledger._conn.execute(
                 "SELECT * FROM evidence").fetchall()))
    assert before == after
    # source tables were not mutated either
    rows = ledger._conn.execute(
        "SELECT COUNT(*) AS n FROM findings").fetchone()
    assert rows["n"] == 0


def test_finalize_shapes_truncation() -> None:
    out = C.finalize([f"v{i:03d}" for i in range(150)], "")
    assert isinstance(out, C.Completion)
    assert len(out.values) == 100 and _total(out) == 150 and _has_more(out)
    assert C.finalize(["b", "a", "a"], "") == ["a", "b"]
    assert C.finalize(["Alpha"], "al") == ["Alpha"]
    assert C.finalize([], "") == []
