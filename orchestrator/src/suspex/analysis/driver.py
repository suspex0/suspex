"""Kernel-driver surface analysis — the static half of `knife drv`.

Recovers from a driver image (file or in-memory dump):

* plausibility — native subsystem OR imports from ntoskrnl/hal/ndis
* device names — ``\\Device\\`` / ``\\DosDevices\\`` / ``\\??\\`` / ``\\\\.\\``
  strings with xref counts and a ``created`` flag when a referencing
  function also calls ``IoCreateDevice*`` / ``IoCreateSymbolicLink``
* IRP dispatch — DriverObject register-copy tracking from DriverEntry
  (rcx at entry) through the entry function's blocks; ``mov [obj+0x70+8n],
  handler`` stores become ``MajorFunction[n]`` entries
* FastIoDispatch — a store to ``DriverObject+0x50`` followed by a
  FAST_IO_DISPATCH table parse (27 named slots)
* IOCTL surface — ``cmp reg/mem, imm>=0x10000`` harvest inside the
  recovered IRP_MJ_DEVICE_CONTROL handler(s), decoded via
  ``conversions.ioctl``
* kernel primitives — import-name match against the BYOVD-relevant API
  classes (physmem map, arbitrary R/W, callbacks, loader, io-port)
  resolved to real call sites via the engine's xref table

Reachability is evidence-honest: primitives are ``confirmed_direct`` when
a call site sits in a function reachable from entry/IRP roots by direct
edges, else ``unresolved``. Never "unreachable".
"""

from __future__ import annotations

import re
from typing import Any

from .reachability import Reachability
from .engine import Analysis, ImageView, Insn

# _DRIVER_OBJECT x64 offsets (WDK; stable since Vista).
DO_DEVICE_OBJECT = 0x08
DO_DRIVER_START = 0x18
DO_DRIVER_SIZE = 0x20
DO_DRIVER_EXTENSION = 0x30
DO_DRIVER_NAME = 0x38      # UNICODE_STRING
DO_HARDWARE_DATABASE = 0x48
DO_FASTIO_DISPATCH = 0x50
DO_DRIVER_INIT = 0x58
DO_DRIVER_STARTIO = 0x60
DO_DRIVER_UNLOAD = 0x68
DO_MAJOR_FUNCTION_BASE = 0x70
DO_MAJOR_FUNCTION_COUNT = 28

IRP_NAMES = [
    "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE", "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION",
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
    "SizeOfFastIoDispatch", "FastIoCheckIfPossible", "FastIoRead",
    "FastIoWrite", "FastIoQueryBasicInfo", "FastIoQueryStandardInfo",
    "FastIoLock", "FastIoUnlockSingle", "FastIoUnlockAll",
    "FastIoUnlockAllByKey", "FastIoDeviceControl",
    "AcquireFileForNtCreateSection", "ReleaseFileForNtCreateSection",
    "FastIoDetachDevice", "FastIoQueryNetworkOpenInfo",
    "AcquireForModWrite", "MdlRead", "MdlReadComplete",
    "PrepareMdlWrite", "MdlWriteComplete", "FastIoReadCompressed",
    "FastIoWriteCompressed", "MdlReadCompleteCompressed",
    "MdlWriteCompleteCompressed", "FastIoQueryOpen",
    "ReleaseForModWrite", "AcquireForCcFlush", "ReleaseForCcFlush",
]

# kernel-primitive classes → import names (the BYOVD-relevant subset of
# knife's ~150-entry ntapi catalog).
KERNEL_PRIMITIVES: dict[str, dict] = {
    "physical-mem": {
        "severity": 3,
        "apis": {"mmmapiospace", "mmmapiospaceex", "mmmaplockedpages",
                 "mmmaplockedpagesspecifycache", "mmgetphysicaladdress",
                 "zwmapviewofsection", "mmmapiospace"},
        "note": "maps physical memory — the classic arbitrary-read primitive"},
    "kernel-rw": {
        "severity": 3,
        "apis": {"mmcopyvirtualmemory", "zwreadvirtualmemory",
                 "zwwritevirtualmemory", "ntreadvirtualmemory",
                 "ntwritevirtualmemory", "kestackattachprocess",
                 "mmcopymemory", "memmove", "memcpy", "rtlcopymemory"},
        "note": "arbitrary kernel/process memory copy"},
    "loader": {
        "severity": 3,
        "apis": {"ntloaddriver", "zwloaddriver", "iocreatedriver",
                 "mmloadsystemimage", "zwsetsysteminformation",
                 "ntsetsysteminformation"},
        "note": "loads additional drivers — chained BYOVD"},
    "callback": {
        "severity": 3,
        "apis": {"obregistercallbacks", "obunregistercallbacks",
                 "pssetcreatprocessnotifyroutine",
                 "pssetcreatprocessnotifyroutineex",
                 "pssetcreatethreadnotifyroutine",
                 "pssetloadimagenotifyroutine", "cmregistercallback",
                 "cmregistercallbackex", "ioregisterbootdriverreinitialization",
                 "ioqueueworkitem", "keinitializedpc",
                 "iosetcompletionroutineex"},
        "note": "kernel callback registration — persistent kernel hooks"},
    "io-port": {
        "severity": 2,
        "apis": {"read_port_uchar", "read_port_ulong", "write_port_uchar",
                 "write_port_ulong", "halgetbusdata", "halsetbusdata"},
        "note": "raw I/O port access — SMBus/MSR-adjacent primitives"},
    "process": {
        "severity": 2,
        "apis": {"zwterminateprocess", "pslookupprocessbyprocessid",
                 "obopenobjectbypointer", "zwopenprocess",
                 "keattachprocess", "iobyname"} ,
        "note": "cross-process manipulation"},
    "registry": {
        "severity": 1,
        "apis": {"zwcreatekey", "zwsetvaluekey", "zwdeletekey",
                 "zwdeletevaluekey", "rtlcreateregistrykey",
                 "rtlwriteregistryvalue", "rtldeleteregistryvalue"},
        "note": "direct kernel registry writes"},
    "security": {
        "severity": 2,
        "apis": {"seaccesscheck", "obreferenceobjectbyhandle",
                 "zwduplicateobject", "ntduplicateobject"},
        "note": "object/token access surface"},
}

_DEVICE_RE = re.compile(
    r"^(?:\\Device\\|\\DosDevices\\|\\\?\?\\|\\\\\.\\).{1,120}$")

_VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}


def plausibly_a_driver(img) -> tuple[bool, str]:
    """(.sys/.drv name) OR (native subsystem AND system-module imports)."""
    if img.subsystem == 1:
        return True, "native subsystem"
    sysmods = {"ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe",
               "ntkrpamp.exe", "hal.dll", "halacpi.dll", "ndis.sys",
               "kdcom.dll", "bootvid.dll", "ci.dll", "clfs.sys",
               "tm.sys", "wdf01000.sys", "wpprecorder.sys"}
    for d in img.imports:
        if d["dll"].lower() in sysmods:
            return True, f"imports {d['dll']}"
    return False, "no native subsystem or kernel imports"


def _entry_function(view: ImageView, analysis: Analysis):
    """The DriverEntry function — the entry seed, or the function whose
    start is the image entry point."""
    img = view.img
    if img is None or not img.entry_rva:
        return None
    return analysis.functions.get(img.image_base + img.entry_rva)


def _track_entry_stores(fn) -> tuple[dict[int, int], int]:
    """Forward pass over DriverEntry's blocks (address order — a
    simplification of knife's intra-block tracking): which DriverObject
    register copies exist, and every ``mov [obj+off], val`` store.

    Returns ``(major_function, fastio_va)`` where major_function maps
    slot index → handler VA.
    """
    drv_regs = {"rcx"}          # DriverEntry(DriverObject=rcx, ...)
    consts: dict[str, int] = {}
    major: dict[int, int] = {}
    fastio_va = 0
    for b in sorted(fn.blocks.values(), key=lambda x: x.start):
        for ins in b.insns:
            m = ins.mnemonic
            ops = ins.ops
            if m == "call":
                for r_ in list(drv_regs & _VOLATILE):
                    drv_regs.discard(r_)
                for r_ in _VOLATILE:
                    consts.pop(r_, None)
                continue
            if len(ops) < 2:
                continue
            dst, src = ops[0], ops[1]
            if m == "mov" and dst["kind"] == "reg" \
                    and src["kind"] == "reg":
                if src["reg"] in drv_regs:
                    drv_regs.add(dst["reg"])
                else:
                    drv_regs.discard(dst["reg"])
                consts.pop(dst["reg"], None)
                if src["reg"] in consts:
                    consts[dst["reg"]] = consts[src["reg"]]
                continue
            if m == "lea" and dst["kind"] == "reg":
                mem = src if src["kind"] == "mem" else ins.mem()
                if mem and mem.get("base") == "rip" and not mem.get("index"):
                    consts[dst["reg"]] = ins.end + mem["disp"]
                else:
                    consts.pop(dst["reg"], None)
                continue
            if m == "mov" and dst["kind"] == "reg":
                iv = ins.imm()
                if iv is not None:
                    consts[dst["reg"]] = iv & 0xFFFFFFFFFFFFFFFF
                else:
                    consts.pop(dst["reg"], None)
                drv_regs.discard(dst["reg"])
                continue
            if m == "mov" and dst["kind"] == "mem" \
                    and dst.get("base") in drv_regs:
                disp = dst.get("disp", 0)
                val = 0
                if src["kind"] == "imm":
                    val = src["imm"] & 0xFFFFFFFFFFFFFFFF
                elif src["kind"] == "reg":
                    val = consts.get(src["reg"], 0)
                if DO_MAJOR_FUNCTION_BASE <= disp < \
                        DO_MAJOR_FUNCTION_BASE + 8 * DO_MAJOR_FUNCTION_COUNT:
                    idx = (disp - DO_MAJOR_FUNCTION_BASE) // 8
                    if val:
                        major[idx] = val
                elif disp == DO_FASTIO_DISPATCH and val:
                    fastio_va = val
                continue
            # any other write to a drv register forgets the copy
            if dst["kind"] == "reg":
                drv_regs.discard(dst["reg"])
                consts.pop(dst["reg"], None)
    return major, fastio_va


def _parse_fastio(view: ImageView, table_va: int) -> list[dict]:
    out = []
    for i, name in enumerate(FASTIO_SLOTS):
        b = view.read(table_va + i * 8, 8)
        if len(b) < 8:
            break
        val = int.from_bytes(b, "little")
        if i == 0:
            continue  # SizeOfFastIoDispatch dword count
        out.append({"slot": name, "index": i,
                    "va": val, "resolved": bool(val)})
    return out


def _ioctl_harvest(fn, view: ImageView) -> list[dict]:
    """``cmp x, imm32 >= 0x10000`` inside a dispatch handler → CTL_CODE."""
    from ..mcp.conversions.ioctl import decode_ctl_code
    out: dict[int, dict] = {}
    for ins in fn.insns():
        if ins.mnemonic not in ("cmp", "sub"):
            continue
        iv = ins.imm()
        if iv is None or not (0x10000 <= iv <= 0xFFFFFFFF):
            continue
        try:
            dec = decode_ctl_code(iv)
        except Exception:
            continue
        row = out.get(iv)
        if row is None:
            row = {"code": iv, "code_hex": dec["code_hex"],
                   "device_type_name": dec["device_type_name"],
                   "method_name": dec["method_name"],
                   "access_name": dec["access_name"],
                   "function": dec["function"],
                   "method_neither": dec["method"] == 3,
                   "sites": []}
            out[iv] = row
        row["sites"].append(f"0x{ins.addr:X}")
    return list(out.values())


def _device_names(view: ImageView, analysis: Analysis) -> list[dict]:
    """Device-looking strings with xref counts and IoCreateDevice* proof."""
    from .extract import find_strings
    data = view._data
    create_apis = {"iocreatedevice", "iocreatedevicesecure",
                   "iocreatesymboliclink", "ioregisterdeviceinterface"}
    create_sites = set()
    for key, refs in analysis.xrefs_to.items():
        if isinstance(key, str) and key.split("!")[-1].lower() in create_apis:
            for r in refs:
                create_sites.add(r["from"])
    create_funcs = set()
    for site in create_sites:
        fn = analysis.function_at(site)
        if fn:
            create_funcs.add(fn.start)
    out = []
    for s in find_strings(data, min_len=4, utf16=True):
        val = s["value"]
        if not _DEVICE_RE.match(val):
            continue
        va = -1
        if view.img is not None:
            va = view.img.off_to_va(s["offset"])
        else:
            va = view.base_va + s["offset"]
        refs = analysis.xrefs_to.get(va, [])
        created = False
        for ref in refs:
            fn = analysis.function_at(ref["from"])
            if fn and fn.start in create_funcs:
                created = True
                break
        out.append({"value": val, "va": va if va >= 0 else None,
                    "kind": s["kind"], "xref_count": len(refs),
                    "created": created})
    return out


def _primitive_callsites(view: ImageView, analysis: Analysis) -> list[dict]:
    """Match kernel-primitive imports to real call sites."""
    import_names = set()
    for d in (view.img.imports if view.img else []):
        for e in d["entries"]:
            if e["name"]:
                import_names.add(e["name"].lower())
    out = []
    for cls, meta in KERNEL_PRIMITIVES.items():
        for api in meta["apis"]:
            if api not in import_names:
                continue
            key = next((k for k in analysis.xrefs_to
                        if isinstance(k, str)
                        and k.split("!")[-1].lower() == api), None)
            sites = [r["from"] for r in
                     analysis.xrefs_to.get(key, [])] if key else []
            funcs = {analysis.function_at(s).start
                     for s in sites if analysis.function_at(s)}
            reach = (Reachability.CONFIRMED_DIRECT if sites
                     else Reachability.UNRESOLVED)
            out.append({"api": api, "class": cls,
                        "severity": meta["severity"],
                        "note": meta["note"],
                        "call_sites": [f"0x{s:X}" for s in sites],
                        "functions": [f"0x{s:X}" for s in sorted(funcs)],
                        "reachability": reach.value})
    out.sort(key=lambda r: (-r["severity"], r["class"], r["api"]))
    return out


def _handler_functions(view: ImageView, analysis: Analysis,
                       handler_vas: list[int]) -> dict[int, Any]:
    """Functions for dispatch handlers — recover the ones the main pass
    never saw (handlers are reached by a *data store* into MajorFunction[],
    not a call edge, so they are absent from the primary call graph)."""
    out = dict(analysis.functions)
    missing = [v for v in handler_vas if v and v not in out]
    if missing:
        from .engine import Engine
        supp = Engine(view).analyze(seeds=missing)
        out.update(supp.functions)
    return out


def _surface(view: ImageView, analysis: Analysis) -> tuple[dict, dict]:
    """Shared body of driver_surface/ioctl_surface — returns the report
    dict plus the (possibly supplemented) function map."""
    img = view.img
    out: dict[str, Any] = {"is_driver": False, "reason": "not a PE"}
    if img is None:
        return out, {}
    is_drv, why = plausibly_a_driver(img)
    out["is_driver"] = is_drv
    out["reason"] = why
    out["entry_va"] = img.image_base + img.entry_rva
    out["devices"] = _device_names(view, analysis)
    out["kernel_primitives"] = _primitive_callsites(view, analysis)

    major: dict[int, int] = {}
    fastio_va = 0
    entry_fn = _entry_function(view, analysis)
    if entry_fn is not None:
        major, fastio_va = _track_entry_stores(entry_fn)
    funcs = _handler_functions(view, analysis,
                               [v for v in major.values()] + [fastio_va])
    dispatch = []
    for idx, va in sorted(major.items()):
        name = IRP_NAMES[idx] if idx < len(IRP_NAMES) else f"IRP_MJ_{idx}"
        fn = funcs.get(va)
        dispatch.append({
            "slot": idx, "name": name, "handler_va": va,
            "handler_name": fn.name if fn else f"sub_{va:X}",
            "resolved": fn is not None,
        })
    out["irp_dispatch"] = dispatch
    if fastio_va:
        out["fastio_dispatch_va"] = fastio_va
        out["fastio"] = _parse_fastio(view, fastio_va)
    out["signed"] = bool(img.cert_size)
    out["cert_size"] = img.cert_size
    return out, funcs


def driver_surface(view: ImageView, analysis: Analysis) -> dict:
    """`bin_manage irp_surface` — the static driver-attack-surface report."""
    out, _funcs = _surface(view, analysis)
    return out


def ioctl_surface(view: ImageView, analysis: Analysis) -> dict:
    """`bin_manage ioctl_surface` — CTL_CODE harvest inside the recovered
    IRP_MJ_DEVICE_CONTROL handler(s)."""
    surface, funcs = _surface(view, analysis)
    handlers = [d for d in surface.get("irp_dispatch", [])
                if d["name"] in ("IRP_MJ_DEVICE_CONTROL",
                                 "IRP_MJ_INTERNAL_DEVICE_CONTROL")]
    iot: list[dict] = []
    for h in handlers:
        fn = funcs.get(h["handler_va"])
        if fn is None:
            continue
        for row in _ioctl_harvest(fn, view):
            row["handler"] = h["handler_name"]
            row["handler_va"] = h["handler_va"]
            iot.append(row)
    return {
        "is_driver": surface["is_driver"],
        "handlers": handlers,
        "ioctl_codes": iot,
        "method_neither_count": sum(1 for r in iot if r["method_neither"]),
        "note": ("compare-constant harvest — a dispatch that selects on a "
                 "computed value (jump table, subtract chain) yields no "
                 "cmp-immediates and is invisible here"),
    }
