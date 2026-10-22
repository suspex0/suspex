"""Tests for _error_enrich — pattern-match raw failure strings to
{kind, hint} pairs the LLM can branch on.

The specific strings covered here are the exact ones from the developer
feedback: `driver: DeviceIoControl gle=299`, `AttachProcess failed
errno_code=1`, `CreateProcess2 failed hr=0x80070057`, "no verified
pattern recipe for build …".
"""
from __future__ import annotations

import pytest

from suspex.mcp._error_enrich import (
    HINT_RULES,
    classify,
    enrich_error,
    enrich_win32,
)


def test_enrich_win32_adds_symbolic_name_for_gle():
    r = enrich_win32("DeviceIoControl gle=87")
    assert "INVALID_PARAMETER" in r


def test_enrich_win32_adds_symbolic_name_for_hr():
    r = enrich_win32("CreateProcess failed hr=0x80070005")
    # 5 is ACCESS_DENIED in the Win32 table
    assert "ACCESS_DENIED" in r


def test_enrich_win32_adds_symbolic_name_for_errno_code():
    r = enrich_win32("AttachProcess failed errno_code=1")
    # 1 is INVALID_FUNCTION
    assert "INVALID_FUNCTION" in r


def test_enrich_win32_leaves_unrelated_text_alone():
    r = enrich_win32("some random error with no code")
    assert r == "some random error with no code"


def test_classify_partial_read():
    kind, hint = classify("DeviceIoControl gle=299")
    assert kind == "partial_read"
    assert "allow_fault" in hint or "partial=true" in hint


def test_classify_attach_denied():
    kind, hint = classify("AttachProcess failed errno_code=1")
    assert kind == "attach_denied"
    assert "capabilities" in hint or "Session 0" in hint


def test_classify_create_process_e_invalidarg():
    kind, hint = classify("CreateProcess2 failed hr=0x80070057")
    assert kind == "create_process_e_invalidarg"
    assert "run_detached" in hint or "exe path" in hint


def test_classify_no_pattern_recipe():
    kind, hint = classify("no verified pattern recipe for build 26200")
    assert kind == "no_pattern_for_build"
    assert "SUSPX_SYMBOL_STORE" in hint or "symbols_manage" in hint


def test_classify_driver_absent():
    kind, hint = classify("driver: DeviceIoControl gle=6")
    assert kind == "driver_absent_or_stale"
    assert "driver_load" in hint


def test_classify_invalid_address_wins_over_driver_prefix():
    """v0.16 regression guard: the agent prefixes every driver-side failure
    with 'driver: DeviceIoControl gle=...', so an INVALID_ADDRESS response
    reaches us as 'driver: DeviceIoControl gle=87 STATUS_INVALID_ADDRESS'.
    The specific NTSTATUS rule must fire before the driver catch-all,
    otherwise the caller sees a driver_absent_or_stale hint and pointlessly
    re-checks driver_load."""
    kind, hint = classify("driver: DeviceIoControl gle=87 STATUS_INVALID_ADDRESS")
    assert kind == "invalid_address"
    assert "probe_va" in hint or "va_translate" in hint


def test_classify_partial_read_wins_over_driver_prefix():
    """Same precedence rule for STATUS_PARTIAL_COPY."""
    kind, hint = classify("driver: DeviceIoControl gle=299 STATUS_PARTIAL_COPY")
    assert kind == "partial_read"
    assert "allow_fault" in hint or "partial=true" in hint


def test_classify_gle59_mmio_read_is_invalid_address():
    """v0.27 regression guard: MmCopyMemory on a BAR/MMIO-backed VA fails
    with an NTSTATUS whose Win32 projection is gle=59 — the driver was
    loaded and healthy; the ADDRESS is the fault. Must not fall through
    to the driver catch-all's driver_load hint."""
    kind, hint = classify("driver: DeviceIoControl gle=59")
    assert kind == "invalid_address"
    assert "driver_load" not in hint


def test_classify_gle59_with_nt_suffix():
    """comm (v0.27) appends the raw NTSTATUS when the failing call was
    NTSTATUS-backed: 'DeviceIoControl gle=59 nt=0xc00000e9'
    (STATUS_UNEXPECTED_IO_ERROR). Both spellings classify."""
    for msg in ("driver: DeviceIoControl gle=59 nt=0xc00000e9",
                "driver: DeviceIoControl nt=0xC00000E9"):
        kind, _ = classify(msg)
        assert kind == "invalid_address", msg


def test_classify_io_device_variants():
    """The rest of the device-I/O family: gle=1117 (ERROR_IO_DEVICE) and
    the raw nt=0xC0000185 (STATUS_IO_DEVICE_ERROR)."""
    for msg in ("driver: DeviceIoControl gle=1117",
                "driver: DeviceIoControl nt=0xC0000185"):
        kind, _ = classify(msg)
        assert kind == "invalid_address", msg


def test_enrich_win32_names_gle59():
    assert "UNEXP_NET_ERR" in enrich_win32("DeviceIoControl gle=59")


def test_enrich_win32_names_nt_unexpected_io():
    r = enrich_win32("DeviceIoControl gle=59 nt=0xc00000e9")
    assert "UNEXP_NET_ERR" in r
    assert "STATUS_UNEXPECTED_IO_ERROR" in r


def test_classify_generic_driver_gle_still_driver_absent():
    """A transport failure with no memory-status marker must NOT be
    swallowed by the MMIO rule — the driver catch-all still stands."""
    kind, _ = classify("driver: DeviceIoControl gle=1168")
    assert kind == "driver_absent_or_stale"


def test_classify_deadline_exceeded():
    kind, hint = classify("StatusCode.DEADLINE_EXCEEDED")
    assert kind == "deadline_exceeded"
    assert "run_detached" in hint or "timeout_s" in hint


def test_classify_unknown_returns_empty_hint():
    kind, hint = classify("some totally unmatched garbage")
    assert kind == "unknown"
    assert hint == ""


def test_enrich_error_full_pipeline():
    r = enrich_error("mem_rw", "read", "kernel gle=299")
    assert r["tool"] == "mem_rw"
    assert r["action"] == "read"
    assert r["kind"] == "partial_read"
    assert "hint" in r
    # Enriched text has the symbolic name expanded
    assert "gle=299" in r["error"]


def test_hint_rules_are_well_formed():
    for pat, kind, hint in HINT_RULES:
        assert kind and isinstance(kind, str)
        assert hint and isinstance(hint, str)
        # pattern must at least compile — the import already tested that
        assert pat.pattern


def test_enrich_error_survives_non_string_input():
    r = enrich_error("tool", "action", 42)      # int
    assert r["tool"] == "tool"
    assert "error" in r
