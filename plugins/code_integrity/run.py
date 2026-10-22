"""code_integrity — live .text vs on-disk image, per-function body hash.

`iat_diff` catches IAT-slot redirection; this plugin catches the class it
can't see: inline patches, hot-patches, and NOP'd prologues inside a
function body. It reads the module's live image from kernel/user memory,
runs the same function-recovery + normalized body-hash the static
``bin_manage diff`` uses, and reports per-function mismatches.

Live-image caveats the report carries honestly:
  * relocs/imports resolved in the live image differ from disk — the
    normalizer masks immediate/displacement bytes, so residual diffs are
    real code changes, not address noise (that's the point of hashing
    mnemonics + operand shapes, not raw bytes)
  * functions recovered on only one side are listed separately — a whole
    new function in the live image is itself a finding
  * a missing/!parseable disk baseline yields ``baseline_unavailable``
"""

from __future__ import annotations

from pathlib import Path

from suspex.sdk import SuspexError

_READ_CHUNK = 0x40000


async def _read_image(sdk, base: int, size: int, *, kernel: bool,
                      view: str) -> bytes:
    space = "kernel" if kernel else "user"
    out = bytearray()
    off = 0
    while off < size:
        n = min(_READ_CHUNK, size - off)
        try:
            chunk = await sdk.mem.read(0, base + off, n, space=space,
                                       view=view)
        except SuspexError:
            chunk = b"\x00" * n          # hole → zero page
        out += chunk[:n]
        off += n
    return bytes(out)


def _hash_map(data: bytes, layout: str, budget: int) -> dict | None:
    try:
        from suspex.analysis import engine as _eng
        from suspex.analysis import pe as _pe
    except ImportError:
        return None
    try:
        img = _pe.parse(data, layout=layout)
    except Exception:
        return None
    kw = {"budget": budget} if budget else {}
    try:
        an = _eng.analyze_image(_eng.ImageView(img), **kw)
    except Exception:
        return None
    out = {}
    for va, f in an.functions.items():
        h = _eng.body_hash(f)
        out.setdefault(h, []).append({
            "rva": va - img.image_base, "name": f.name,
            "size": f.size, "blocks": len(f.blocks)})
    return out


async def run(sdk, params: dict) -> dict:
    module = str(params["module"])
    pid = int(params.get("pid") or 0)
    kernel = bool(params.get("kernel", True))
    view = str(params.get("view") or ("kernel" if kernel else "user"))
    budget = int(params.get("budget") or 0)
    disk_path = str(params.get("disk_path") or "")

    # --- live image -------------------------------------------------------
    mods = await sdk.mods.list(pid, kernel=kernel, view=view)
    hit = None
    mlow = module.lower()
    for m in mods:
        mname = str(m.get("name") or "").split("\\")[-1].lower()
        if mname == mlow or str(m.get("path") or "").lower().endswith(mlow):
            hit = m
            break
    if hit is None:
        return {"ok": False, "kind": "module_not_found",
                "error": f"{module!r} not in the live module list"}
    base, size = int(hit.get("base", 0)), int(hit.get("size", 0))
    live = await _read_image(sdk, base, size, kernel=kernel, view=view)

    # --- disk baseline ----------------------------------------------------
    if not disk_path or not Path(disk_path).is_file():
        return {"ok": False, "kind": "baseline_unavailable",
                "error": "disk_path missing or unreadable — supply the "
                         "on-disk copy (file_manage download it first)",
                "module": module, "base": base, "size": size}
    disk = Path(disk_path).read_bytes()

    a = _hash_map(live, "image", budget)     # live: image layout
    b = _hash_map(disk, "file", budget)      # disk: file layout
    if a is None or b is None:
        return {"ok": False, "kind": "analysis_failed",
                "error": "function recovery failed on one side "
                         "(capstone extra missing or unparseable image)",
                "module": module}

    changed, only_live, only_disk = [], [], []
    for h, rows in a.items():
        if h not in b:
            only_live.extend(rows)
    for h, rows in b.items():
        if h not in a:
            only_disk.extend(rows)
    # pair same-position diffs as "changed" candidates
    for r in only_live:
        peer = next((d for d in only_disk if d["rva"] == r["rva"]), None)
        if peer is not None:
            changed.append({"rva": r["rva"], "name": r["name"],
                            "live_size": r["size"], "disk_size": peer["size"],
                            "verdict": "body_mismatch"})
            only_disk.remove(peer)
        else:
            changed.append({**r, "verdict": "live_only"})
    for r in only_disk:
        changed.append({**r, "verdict": "disk_only"})

    return {
        "ok": True,
        "severity": "high" if any(c["verdict"] == "body_mismatch"
                                  for c in changed) else "info",
        "summary": (f"{module}: {len(changed)} function bodies differ "
                    f"({sum(1 for c in changed if c['verdict']=='body_mismatch')} "
                    f"mismatched, {sum(1 for c in changed if c['verdict']=='live_only')} "
                    f"live-only, {sum(1 for c in changed if c['verdict']=='disk_only')} "
                    f"disk-only)"),
        "module": module, "base": base, "size": size,
        "functions_live": sum(len(v) for v in a.values()),
        "functions_disk": sum(len(v) for v in b.values()),
        "identical": len(set(a) & set(b)),
        "changed": changed,
        "note": ("body hashes are mnemonic+operand-shape normalized, so "
                 "relocated immediates don't diff; a mismatch means the "
                 "instruction stream itself changed (inline patch, "
                 "hot-patch, self-modifying code)"),
    }
