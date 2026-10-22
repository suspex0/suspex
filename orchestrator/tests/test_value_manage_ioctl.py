"""Tests for value_manage ioctl_decode / ioctl_encode (CTL_CODE fields).

Covers the bit layout (device/access/function/method), method and
FILE_DEVICE_* naming, vendor-range warnings, the METHOD_NEITHER flag,
name-based encode inputs, and the encode∘decode round-trip.
"""
from __future__ import annotations

import pytest

from suspex.mcp.conversions import ConversionError
from suspex.mcp import value_ops


class TestIoctlDecode:
    def test_known_code_method_out_direct(self) -> None:
        # 0x500016: device 0x50, function 5, METHOD_OUT_DIRECT — same
        # regression vector knife carries.
        r = value_ops.dispatch("ioctl_decode", value="0x500016")
        assert r["ok"] is True
        assert r["device_type"] == 0x50
        assert r["function"] == 5
        assert r["method_name"] == "METHOD_OUT_DIRECT"
        assert r["access"] == 0

    def test_int_input(self) -> None:
        r = value_ops.dispatch("ioctl_decode", value=0x500016)
        assert r["code"] == 0x500016

    def test_named_device_type(self) -> None:
        # CTL_CODE(FILE_DEVICE_DISK=0x7, 0x700, METHOD_BUFFERED, READ|WRITE)
        r = value_ops.dispatch("ioctl_decode", value=0x7DC00)
        assert r["device_type_name"] == "FILE_DEVICE_DISK"
        assert r["method_name"] == "METHOD_BUFFERED"
        assert r["access_name"] == "FILE_READ_ACCESS|FILE_WRITE_ACCESS"

    def test_method_neither_warns(self) -> None:
        r = value_ops.dispatch("ioctl_decode", value=0x220003)
        assert r["method_name"] == "METHOD_NEITHER"
        assert any("METHOD_NEITHER" in w for w in r["warnings"])

    def test_vendor_defined_function_warns(self) -> None:
        r = value_ops.dispatch("ioctl_decode", value=0x222000)
        assert r["function"] == 0x800
        assert r["function_class"] == "vendor_defined"
        assert any("vendor-defined" in w for w in r["warnings"])

    def test_vendor_device_class(self) -> None:
        r = value_ops.dispatch("ioctl_decode", value=0x80000000)
        assert r["device_type_class"] == "vendor_defined"
        assert r["device_type_name"] is None

    def test_overflow_refused(self) -> None:
        with pytest.raises(ConversionError) as ei:
            value_ops.dispatch("ioctl_decode", value="0x100000000")
        assert ei.value.kind == "overflow"


class TestIoctlEncode:
    def test_named_fields(self) -> None:
        r = value_ops.dispatch(
            "ioctl_encode",
            device_type="FILE_DEVICE_UNKNOWN", function="0x803",
            method="METHOD_NEITHER", access="FILE_ANY_ACCESS")
        assert r["ok"] is True
        assert r["code"] == 0x22200F
        assert r["method_name"] == "METHOD_NEITHER"

    def test_int_fields(self) -> None:
        r = value_ops.dispatch(
            "ioctl_encode", device_type=0x7, function=0x700,
            method=0, access=3)
        assert r["code"] == 0x7DC00

    def test_lenient_access_spelling(self) -> None:
        r = value_ops.dispatch(
            "ioctl_encode", device_type=0x22, function=0x100,
            method="buffered", access="read_write")
        assert r["access_name"] == "FILE_READ_ACCESS|FILE_WRITE_ACCESS"

    def test_field_overflow_refused(self) -> None:
        with pytest.raises(ConversionError) as ei:
            value_ops.dispatch(
                "ioctl_encode", device_type=0x22, function=0x1000,
                method=0, access=0)
        assert ei.value.kind == "overflow"

    def test_unknown_name_refused(self) -> None:
        with pytest.raises(ConversionError) as ei:
            value_ops.dispatch(
                "ioctl_encode", device_type="NOPE", function=0x100,
                method=0, access=0)
        assert ei.value.kind == "unparseable_value"


class TestRoundTrip:
    @pytest.mark.parametrize("code", [
        0x0, 0x500016, 0x7DC00, 0x22200F, 0x80002000, 0xFFFFFFFF,
    ])
    def test_decode_of_encode_is_identity(self, code: int) -> None:
        dec = value_ops.dispatch("ioctl_decode", value=code)
        enc = value_ops.dispatch(
            "ioctl_encode",
            device_type=dec["device_type"], function=dec["function"],
            method=dec["method"], access=dec["access"])
        assert enc["code"] == code


class TestDispatchIntegration:
    def test_actions_registered(self) -> None:
        assert "ioctl_decode" in value_ops.VALUE_MANAGE_ACTIONS
        assert "ioctl_encode" in value_ops.VALUE_MANAGE_ACTIONS

    def test_ioctl_actions_not_heavy(self) -> None:
        assert "ioctl_decode" not in value_ops.HEAVY_ACTIONS
        assert "ioctl_encode" not in value_ops.HEAVY_ACTIONS
