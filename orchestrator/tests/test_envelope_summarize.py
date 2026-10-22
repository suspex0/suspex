"""v0.17 A-4: ``summarize_ops`` helper on the envelope module.

Aggregates a ``recent_ops`` ring (list of
``{method, elapsed_ms, ok, ts, ...}`` rows) into a per-method
summary. Agent E wires it at the ``target_manage recent_ops`` action
site; this file locks the helper's contract.

Coverage:

  * Groups by ``method``.
  * ``count`` / ``ok_count`` / ``err_count`` add up.
  * ``min_ms`` / ``max_ms`` / ``avg_ms`` compute correctly.
  * ``last_ts`` is the newest timestamp per method.
  * Sorted busiest-first.
  * Empty input returns empty list.
  * Missing / falsy fields fall back to zero without crashing.
"""

from __future__ import annotations

from suspex.mcp._envelope import summarize_ops


def test_summarize_empty_returns_empty_list():
    assert summarize_ops([]) == []


def test_summarize_groups_by_method():
    rows = [
        {"method": "AttachProcess", "elapsed_ms": 10, "ok": True, "ts": 1},
        {"method": "AttachProcess", "elapsed_ms": 20, "ok": True, "ts": 2},
        {"method": "ReadMemory",    "elapsed_ms": 5,  "ok": True, "ts": 3},
    ]
    out = summarize_ops(rows)
    methods = {r["method"] for r in out}
    assert methods == {"AttachProcess", "ReadMemory"}


def test_summarize_ok_err_counts():
    rows = [
        {"method": "Read", "elapsed_ms": 1, "ok": True,  "ts": 1},
        {"method": "Read", "elapsed_ms": 1, "ok": True,  "ts": 2},
        {"method": "Read", "elapsed_ms": 1, "ok": False, "ts": 3},
        {"method": "Read", "elapsed_ms": 1, "ok": False, "ts": 4},
        {"method": "Read", "elapsed_ms": 1, "ok": False, "ts": 5},
    ]
    (row,) = summarize_ops(rows)
    assert row["count"] == 5
    assert row["ok_count"] == 2
    assert row["err_count"] == 3


def test_summarize_latency_stats():
    rows = [
        {"method": "M", "elapsed_ms": 10, "ok": True, "ts": 1},
        {"method": "M", "elapsed_ms": 30, "ok": True, "ts": 2},
        {"method": "M", "elapsed_ms": 20, "ok": True, "ts": 3},
    ]
    (row,) = summarize_ops(rows)
    assert row["min_ms"] == 10
    assert row["max_ms"] == 30
    assert row["avg_ms"] == 20.0


def test_summarize_avg_correct_with_single_row():
    rows = [{"method": "M", "elapsed_ms": 42, "ok": True, "ts": 1}]
    (row,) = summarize_ops(rows)
    assert row["count"] == 1
    assert row["min_ms"] == 42
    assert row["max_ms"] == 42
    assert row["avg_ms"] == 42.0


def test_summarize_avg_rounded_to_one_decimal():
    rows = [
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 1},
        {"method": "M", "elapsed_ms": 2, "ok": True, "ts": 2},
        {"method": "M", "elapsed_ms": 2, "ok": True, "ts": 3},
    ]
    (row,) = summarize_ops(rows)
    # (1 + 2 + 2) / 3 == 1.666... → 1.7
    assert row["avg_ms"] == 1.7


def test_summarize_last_ts_is_newest():
    rows = [
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 100},
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 500},
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 300},
    ]
    (row,) = summarize_ops(rows)
    assert row["last_ts"] == 500


def test_summarize_sorted_busiest_first():
    rows = [
        {"method": "A", "elapsed_ms": 1, "ok": True, "ts": 1},
        {"method": "B", "elapsed_ms": 1, "ok": True, "ts": 1},
        {"method": "B", "elapsed_ms": 1, "ok": True, "ts": 2},
        {"method": "B", "elapsed_ms": 1, "ok": True, "ts": 3},
        {"method": "C", "elapsed_ms": 1, "ok": True, "ts": 1},
        {"method": "C", "elapsed_ms": 1, "ok": True, "ts": 2},
    ]
    out = summarize_ops(rows)
    assert [r["method"] for r in out] == ["B", "C", "A"]
    assert [r["count"] for r in out] == [3, 2, 1]


def test_summarize_missing_method_falls_back_to_question_mark():
    rows = [
        {"elapsed_ms": 5, "ok": True, "ts": 1},  # no method key
        {"method": "", "elapsed_ms": 5, "ok": True, "ts": 2},
    ]
    out = summarize_ops(rows)
    methods = sorted(r["method"] for r in out)
    # Empty string and missing method both stringify to "?" / "" —
    # helper coerces to str, so "" stays "" and missing becomes "?".
    assert methods == ["", "?"]


def test_summarize_missing_elapsed_ms_treated_as_zero():
    rows = [
        {"method": "M", "ok": True, "ts": 1},        # no elapsed_ms
        {"method": "M", "elapsed_ms": None, "ok": True, "ts": 2},
        {"method": "M", "elapsed_ms": 10, "ok": True, "ts": 3},
    ]
    (row,) = summarize_ops(rows)
    assert row["min_ms"] == 0
    assert row["max_ms"] == 10


def test_summarize_missing_ok_counts_as_error():
    """``ok`` absent or falsy counts as an error — matches how the
    ``AgentClient._recent_ops`` ring records failures."""
    rows = [
        {"method": "M", "elapsed_ms": 1, "ts": 1},           # no ok
        {"method": "M", "elapsed_ms": 1, "ok": None, "ts": 2},
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 3},
    ]
    (row,) = summarize_ops(rows)
    assert row["ok_count"] == 1
    assert row["err_count"] == 2


def test_summarize_missing_ts_treated_as_zero():
    rows = [
        {"method": "M", "elapsed_ms": 1, "ok": True},        # no ts
        {"method": "M", "elapsed_ms": 1, "ok": True, "ts": 0},
    ]
    (row,) = summarize_ops(rows)
    assert row["last_ts"] == 0
