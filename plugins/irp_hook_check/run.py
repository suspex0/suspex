"""irp_hook_check — live DRIVER_OBJECT dispatch table vs static expectation.

Reads the live ``_DRIVER_OBJECT`` at ``driver_object`` (kernel VA) and
extracts ``MajorFunction[28]`` (+0x70) plus ``FastIoDispatch`` (+0x50).
When ``module_path`` resolves to a parseable PE, the static ``irp_surface``
pass recovers the driver's *expected* dispatch entries; each live slot is
then classified:

  matched          — live pointer == DriverStart + static RVA
  patched_inside   — differs from static but still inside the module
                     image (runtime rebind or in-module trampoline)
  redirected_out   — points outside [DriverStart, DriverStart+DriverSize)
                     entirely — the classic IRP hook
  unresolved_live  — live read failed / slot null where static expected
                     a handler
  unresolved_static— slot live but no static evidence; absence of static
                     proof is NOT proof of a hook (knife convention)

Without ``module_path`` the plugin still flags ``redirected_out`` rows —
a dispatch pointer outside its own module needs no baseline to be wrong.
"""

from __future__ import annotations

from pathlib import Path

from suspex.sdk import Reader, SuspexError

# _DRIVER_OBJECT x64 offsets (see analysis/driver.py for the same table).
_DO = {
    "DeviceObject": 0x08, "DriverStart": 0x18, "DriverSize": 0x20,
    "DriverExtension": 0x30, "DriverName": 0x38, "FastIoDispatch": 0x50,
    "DriverInit": 0x58, "DriverStartIo": 0x60, "DriverUnload": 0x68,
    "MajorFunction": 0x70,
}
_MAJOR_COUNT = 28
_FASTIO_COUNT = 28  # slot 0 is SizeOfFastIoDispatch

IRP_NAMES = [
    "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE",
    "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION", "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP", "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA", "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP",
]

FASTIO_SLOTS = [
    "FastIoCheckIfPossible", "FastIoRead", "FastIoWrite",
    "FastIoQueryBasicInfo", "FastIoQueryStandardInfo", "FastIoLock",
    "FastIoUnlockSingle", "FastIoUnlockAll", "FastIoUnlockAllByKey",
    "FastIoDeviceControl", "AcquireFileForNtCreateSection",
    "ReleaseFileForNtCreateSection", "FastIoDetachDevice",
    "FastIoQueryNetworkOpenInfo", "AcquireForModWrite", "MdlRead",
    "MdlReadComplete", "PrepareMdlWrite", "MdlWriteComplete",
    "FastIoReadCompressed", "FastIoWriteCompressed",
    "MdlReadCompleteCompressed", "MdlWriteCompleteCompressed",
    "FastIoQueryOpen", "ReleaseForModWrite", "AcquireForCcFlush",
    "ReleaseForCcFlush",
]


def _kr(sdk, view: str) -> Reader:
    return Reader(lambda addr, n: sdk.mem.read(
        0, addr, n, space="kernel", view=view or "kernel"))


async def _live_surface(r: Reader, obj: int) -> dict:
    """Read the live _DRIVER_OBJECT fields we diff on."""
    out: dict = {"driver_object": obj}
    out["driver_start"] = await r.u64(obj + _DO["DriverStart"])
    out["driver_size"] = await r.u32(obj + _DO["DriverSize"])
    name_ptr = await r.u64(obj + _DO["DriverName"] + 0x8)
    name_len = await r.u16(obj + _DO["DriverName"])
    out["driver_name"] = (await r.wstr(name_ptr, name_len // 2)
                          if name_ptr and name_len else "")
    out["fastio_va"] = await r.u64(obj + _DO["FastIoDispatch"])
    major = []
    for i in range(_MAJOR_COUNT):
        major.append(await r.u64(obj + _DO["MajorFunction"] + i * 8))
    out["major"] = major
    fastio = []
    if out["fastio_va"]:
        for i in range(1, _FASTIO_COUNT):
            try:
                fastio.append(await r.u64(out["fastio_va"] + i * 8))
            except SuspexError:
                fastio.append(0)
    out["fastio"] = fastio
    return out


def _static_surface(module_path: str) -> dict | None:
    """Expected dispatch entries from the on-disk image. Returns None when
    the file can't be parsed/analyzed — callers then fall back to the
    outside-module check only."""
    try:
        from suspex.analysis import driver as _drv
        from suspex.analysis import engine as _eng
        from suspex.analysis import pe as _pe
    except ImportError:
        return None
    p = Path(module_path)
    if not p.is_file():
        return None
    data = p.read_bytes()
    img = None
    for lay in ("file", "image"):
        try:
            img = _pe.parse(data, layout=lay)
            break
        except Exception:
            continue
    if img is None:
        return None
    try:
        an = _eng.analyze_image(_eng.ImageView(img))
    except Exception:
        return None
    surf = _drv.driver_surface(_eng.ImageView(img), an)
    expected: dict[int, int] = {}   # slot -> rva
    for d in surf.get("irp_dispatch", []):
        if d.get("handler_va"):
            expected[d["slot"]] = d["handler_va"] - img.image_base
    fastio: dict[int, int] = {}
    for row in surf.get("fastio", []):
        if row.get("va"):
            fastio[row["index"]] = row["va"] - img.image_base
    return {"expected_major_rva": expected, "expected_fastio_rva": fastio,
            "is_driver": surf.get("is_driver", False)}


def _classify(live: int, expected_rva: int | None, base: int,
              size: int) -> str:
    """One slot's verdict."""
    inside = base <= live < base + size if size else False
    if expected_rva is None:
        return ("redirected_out" if live and not inside
                else "unresolved_static")
    expected_live = base + expected_rva
    if live == expected_live:
        return "matched"
    if not live:
        return "unresolved_live"
    return "patched_inside" if inside else "redirected_out"


async def run(sdk, params: dict) -> dict:
    obj_raw = params.get("driver_object")
    try:
        obj = int(obj_raw) if isinstance(obj_raw, int) else \
            int(str(obj_raw), 0)
    except (TypeError, ValueError):
        return {"ok": False, "kind": "bad_arg",
                "error": f"driver_object {obj_raw!r} is not a VA"}
    view = str(params.get("view") or "kernel")
    module_path = str(params.get("module_path") or "")

    r = _kr(sdk, view)
    try:
        live = await _live_surface(r, obj)
    except SuspexError as exc:
        return {"ok": False, "kind": "read_failed",
                "error": f"kernel read of _DRIVER_OBJECT failed: {exc}"}

    base, size = live["driver_start"], live["driver_size"]
    static = _static_surface(module_path) if module_path else None

    slots = []
    findings = 0
    for i, va in enumerate(live["major"]):
        name = IRP_NAMES[i] if i < len(IRP_NAMES) else f"IRP_MJ_{i}"
        exp = static["expected_major_rva"].get(i) if static else None
        verdict = _classify(va, exp, base, size)
        if verdict in ("redirected_out", "patched_inside"):
            findings += 1
        slots.append({"slot": i, "name": name, "live": va,
                      "expected_rva": exp, "verdict": verdict})
    fastio_rows = []
    if live["fastio_va"]:
        for i, va in enumerate(live["fastio"], start=1):
            name = (FASTIO_SLOTS[i - 1] if i - 1 < len(FASTIO_SLOTS)
                    else f"fastio_{i}")
            exp = (static["expected_fastio_rva"].get(i)
                   if static else None)
            verdict = _classify(va, exp, base, size)
            if verdict in ("redirected_out", "patched_inside"):
                findings += 1
            fastio_rows.append({"slot": name, "index": i, "live": va,
                                "expected_rva": exp, "verdict": verdict})

    verdict_counts: dict[str, int] = {}
    for row in slots + fastio_rows:
        verdict_counts[row["verdict"]] = verdict_counts.get(
            row["verdict"], 0) + 1

    return {
        "ok": True,
        "severity": "high" if findings else "info",
        "summary": (f"{live['driver_name'] or hex(obj)}: {findings} "
                    f"dispatch entries redirected/patched "
                    f"({verdict_counts.get('matched', 0)} matched)"),
        "driver_name": live["driver_name"],
        "driver_object": obj,
        "driver_start": base,
        "driver_size": size,
        "static_baseline": bool(static),
        "major_function": slots,
        "fastio": fastio_rows,
        "verdict_counts": verdict_counts,
        "note": ("'unresolved_static' = live pointer present but no "
                 "static evidence — not proof of a hook. "
                 "'redirected_out' needs no baseline: the pointer left "
                 "its own module."),
    }
