"""CTL_CODE (IOCTL) encode/decode — the bit layout every driver dispatch
handler pokes at.

Layout (ntddk.h):  [31:16] DeviceType  [15:14] Access  [13:2] Function  [1:0] Method
"""

from __future__ import annotations

from typing import Any

from .errors import ConversionError
from .ints import parse_int

# ---------------------------------------------------------------------------
# Method names (the low 2 bits) — METHOD_NEITHER is the dangerous one: the
# buffer pointers sail in raw with no probing, which is why audit tooling
# flags it.
# ---------------------------------------------------------------------------

METHOD_NAMES: dict[int, str] = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}
_METHOD_BY_NAME = {v: k for k, v in METHOD_NAMES.items()}
_METHOD_BY_NAME.update({  # lenient spellings
    "BUFFERED": 0, "IN_DIRECT": 1, "OUT_DIRECT": 2, "NEITHER": 3,
})

ACCESS_NAMES: dict[int, str] = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
}
_ACCESS_BY_NAME = {v: k for k, v in ACCESS_NAMES.items()}
_ACCESS_BY_NAME.update({  # lenient spellings
    "ANY": 0, "READ": 1, "WRITE": 2, "READ_WRITE": 3, "READ|WRITE": 3,
})

# Standard FILE_DEVICE_* values (wdm.h / ntddk.h). Vendor-defined device
# types live at >= 0x8000; vendor-defined function codes at >= 0x800.
DEVICE_TYPE_NAMES: dict[int, str] = {
    0x0001: "FILE_DEVICE_BEEP", 0x0002: "FILE_DEVICE_CD_ROM",
    0x0003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM", 0x0004: "FILE_DEVICE_CONTROLLER",
    0x0005: "FILE_DEVICE_DATALINK", 0x0006: "FILE_DEVICE_DFS",
    0x0007: "FILE_DEVICE_DISK", 0x0008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x0009: "FILE_DEVICE_FILE_SYSTEM", 0x000A: "FILE_DEVICE_INPORT_PORT",
    0x000B: "FILE_DEVICE_KEYBOARD", 0x000C: "FILE_DEVICE_MAILSLOT",
    0x000D: "FILE_DEVICE_MIDI_IN", 0x000E: "FILE_DEVICE_MIDI_OUT",
    0x000F: "FILE_DEVICE_MOUSE", 0x0010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x0011: "FILE_DEVICE_NAMED_PIPE", 0x0012: "FILE_DEVICE_NETWORK",
    0x0013: "FILE_DEVICE_NETWORK_BROWSER",
    0x0014: "FILE_DEVICE_NETWORK_FILE_SYSTEM", 0x0015: "FILE_DEVICE_NULL",
    0x0016: "FILE_DEVICE_PARALLEL_PORT", 0x0017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x0018: "FILE_DEVICE_PRINTER", 0x0019: "FILE_DEVICE_SCANNER",
    0x001A: "FILE_DEVICE_SERIAL_MOUSE_PORT", 0x001B: "FILE_DEVICE_SERIAL_PORT",
    0x001C: "FILE_DEVICE_SCREEN", 0x001D: "FILE_DEVICE_SOUND",
    0x001E: "FILE_DEVICE_STREAMS", 0x001F: "FILE_DEVICE_TAPE",
    0x0020: "FILE_DEVICE_TAPE_FILE_SYSTEM", 0x0021: "FILE_DEVICE_TRANSPORT",
    0x0022: "FILE_DEVICE_UNKNOWN", 0x0023: "FILE_DEVICE_VIDEO",
    0x0024: "FILE_DEVICE_VIRTUAL_DISK", 0x0025: "FILE_DEVICE_WAVE_IN",
    0x0026: "FILE_DEVICE_WAVE_OUT", 0x0027: "FILE_DEVICE_8042_PORT",
    0x0028: "FILE_DEVICE_NETWORK_REDIRECTOR", 0x0029: "FILE_DEVICE_BATTERY",
    0x002A: "FILE_DEVICE_BUS_EXTENDER", 0x002B: "FILE_DEVICE_MODEM",
    0x002C: "FILE_DEVICE_VDM", 0x002D: "FILE_DEVICE_MASS_STORAGE",
    0x002E: "FILE_DEVICE_SMB", 0x002F: "FILE_DEVICE_KS",
    0x0030: "FILE_DEVICE_CHANGER", 0x0031: "FILE_DEVICE_SMARTCARD",
    0x0032: "FILE_DEVICE_ACPI", 0x0033: "FILE_DEVICE_DVD",
    0x0034: "FILE_DEVICE_FULLSCREEN_VIDEO",
    0x0035: "FILE_DEVICE_DFS_FILE_SYSTEM", 0x0036: "FILE_DEVICE_DFS_VOLUME",
    0x0037: "FILE_DEVICE_SERENUM", 0x0038: "FILE_DEVICE_TERMSRV",
    0x0039: "FILE_DEVICE_KSEC", 0x003A: "FILE_DEVICE_FIPS",
    0x003B: "FILE_DEVICE_INFINIBAND", 0x003E: "FILE_DEVICE_VMBUS",
    0x003F: "FILE_DEVICE_CRYPT_PROVIDER", 0x0040: "FILE_DEVICE_WPD",
    0x0041: "FILE_DEVICE_BLUETOOTH", 0x0042: "FILE_DEVICE_MT_COMPOSITE",
    0x0043: "FILE_DEVICE_MT_TRANSPORT", 0x0044: "FILE_DEVICE_BIOMETRIC",
    0x0045: "FILE_DEVICE_PMI", 0x0046: "FILE_DEVICE_EHSTOR",
    0x0047: "FILE_DEVICE_DEVAPI", 0x0048: "FILE_DEVICE_GPIO",
    0x0049: "FILE_DEVICE_USBEX", 0x004A: "FILE_DEVICE_CONSOLE",
    0x004B: "FILE_DEVICE_NFP", 0x004C: "FILE_DEVICE_SYSENV",
    0x004D: "FILE_DEVICE_VIRTUAL_BLOCK", 0x004E: "FILE_DEVICE_POINT_OF_SERVICE",
    0x004F: "FILE_DEVICE_STORAGE_REPLICATION", 0x0050: "FILE_DEVICE_TRUST_ENV",
    0x0051: "FILE_DEVICE_UCM", 0x0052: "FILE_DEVICE_UCMTCPCI",
    0x0053: "FILE_DEVICE_PERSISTENT_MEMORY", 0x0054: "FILE_DEVICE_NVDIMM",
    0x0055: "FILE_DEVICE_HOLOGRAPHIC", 0x0056: "FILE_DEVICE_SDFXAUDIO",
}
_DEVICE_TYPE_BY_NAME = {v: k for k, v in DEVICE_TYPE_NAMES.items()}

_VENDOR_DEVICE_MIN = 0x8000
_VENDOR_FUNCTION_MIN = 0x800


def decode_ctl_code(value: Any) -> dict[str, Any]:
    """Decode a u32 IOCTL code into its CTL_CODE fields."""
    iv = parse_int(value)
    if iv < 0 or iv > 0xFFFFFFFF:
        raise ConversionError(
            "overflow", f"ioctl code {iv:#x} does not fit in u32",
            hint="CTL_CODE is a 32-bit field")
    device_type = (iv >> 16) & 0xFFFF
    access = (iv >> 14) & 0x3
    function = (iv >> 2) & 0xFFF
    method = iv & 0x3
    warnings: list[str] = []
    if method == 3:
        warnings.append(
            "METHOD_NEITHER — neither the input nor output buffer is "
            "probed; the handler must validate user pointers itself")
    if function >= _VENDOR_FUNCTION_MIN:
        warnings.append(
            f"function 0x{function:X} is in the vendor-defined range "
            "(>= 0x800)")
    out: dict[str, Any] = {
        "code": iv,
        "code_hex": f"0x{iv:X}",
        "device_type": device_type,
        "device_type_hex": f"0x{device_type:X}",
        "device_type_name": DEVICE_TYPE_NAMES.get(device_type),
        "function": function,
        "function_hex": f"0x{function:X}",
        "method": method,
        "method_name": METHOD_NAMES[method],
        "access": access,
        "access_name": ACCESS_NAMES[access],
    }
    if device_type >= _VENDOR_DEVICE_MIN:
        out["device_type_class"] = "vendor_defined"
    else:
        out["device_type_class"] = "microsoft"
    out["function_class"] = ("vendor_defined"
                             if function >= _VENDOR_FUNCTION_MIN
                             else "microsoft")
    if warnings:
        out["warnings"] = warnings
    return out


def encode_ctl_code(device_type: Any, function: Any, method: Any,
                    access: Any) -> dict[str, Any]:
    """Inverse of decode_ctl_code — build a CTL_CODE from named fields.

    device_type / method / access accept ints or names
    (``FILE_DEVICE_DISK``, ``METHOD_BUFFERED``, ``FILE_ANY_ACCESS``).
    """
    dt = _resolve_named(device_type, _DEVICE_TYPE_BY_NAME, "device_type")
    fn = _resolve_named(function, {}, "function")
    mt = _resolve_named(method, _METHOD_BY_NAME, "method")
    ac = _resolve_named(access, _ACCESS_BY_NAME, "access")
    for name, v, hi in (("device_type", dt, 0xFFFF), ("function", fn, 0xFFF),
                        ("method", mt, 0x3), ("access", ac, 0x3)):
        if v < 0 or v > hi:
            raise ConversionError(
                "overflow", f"{name} {v:#x} does not fit its CTL_CODE field",
                hint=f"{name} max is {hi:#x}")
    code = ((dt << 16) | (ac << 14) | (fn << 2) | mt) & 0xFFFFFFFF
    out = decode_ctl_code(code)
    out["action_input"] = {"device_type": device_type, "function": function,
                           "method": method, "access": access}
    return out


def _resolve_named(v: Any, names: dict[str, int], field: str) -> int:
    if isinstance(v, str):
        key = v.strip().upper()
        if key in names:
            return names[key]
    try:
        return parse_int(v)
    except ConversionError:
        known = ", ".join(sorted(names)) if names else "int or 0x… only"
        raise ConversionError(
            "unparseable_value", f"{field} {v!r} is not a known name or int",
            hint=f"known {field} values: {known}")
