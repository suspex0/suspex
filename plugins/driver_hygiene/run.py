"""Driver hygiene — cross-check registered services vs loaded modules vs
on-disk .sys files.

Detects five anomaly classes:

  * orphan       — service key exists, ImagePath resolves to a missing file
  * phantom      — service Start<=2 (Boot/System/Auto) but not currently loaded
  * uncanonical  — service ImagePath outside C:\\Windows\\System32\\drivers\\
  * duplicate    — two service keys pointing at the same .sys
  * leftover     — .sys file present on disk with no matching service key

Fully read-only; the entire cross-check is one Services enum + one
kernel-modules list + one list_dir under System32\\drivers.
"""
from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_CANONICAL_DIR = r"C:\Windows\System32\drivers".lower()
_CANONICAL_PREFIX = r"c:\windows\system32\drivers\\"

# --- Helpers ---------------------------------------------------------------

def _resolve_image_path(raw: str) -> str:
    r"""ImagePath is typically of the form '\SystemRoot\System32\drivers\foo.sys'
    or '\??\C:\Windows\System32\drivers\foo.sys' or 'System32\drivers\foo.sys'.
    Normalize to an absolute C:\ path (best-effort)."""
    if not raw:
        return ""
    s = raw.strip().strip('"').strip("'")
    low = s.lower()
    if low.startswith(r"\??\\"):
        return s[4:]
    if low.startswith(r"\??\?\\"):
        return s[6:]
    if low.startswith(r"\systemroot\\"):
        return r"C:\Windows" + s[len(r"\systemroot"):]
    if low.startswith("system32\\"):
        return r"C:\Windows\\" + s
    if low.startswith(r"\\?\\"):
        return s[4:]
    if low.startswith("c:") or low.startswith("d:"):
        return s
    return s


def _is_canonical(path: str) -> bool:
    return path.lower().startswith(_CANONICAL_PREFIX)


async def _enumerate_services(client) -> list[dict]:
    try:
        enum = await client.reg_enum("HKLM", _SERVICES_KEY,
                                      want_subkeys=True, want_values=False)
    except Exception:
        return []
    out: list[dict] = []
    for name in enum.get("subkeys", []):
        key = f"{_SERVICES_KEY}\\{name}"
        row: dict[str, Any] = {"name": name, "subkey": key}
        for value in ("ImagePath", "Start", "Type", "DisplayName", "Group",
                      "ObjectName"):
            try:
                v = await client.reg_get("HKLM", key, value)
            except Exception:
                continue
            row[value.lower()] = (v.get("str") or v.get("qword")
                                   or v.get("hex") or "")
        svc_type = row.get("type", 0)
        if not isinstance(svc_type, int):
            try: svc_type = int(svc_type)
            except Exception: svc_type = 0
        # Filter down to kernel_driver + fs_driver only.
        if (svc_type & 0xFF) not in (0x001, 0x002):
            continue
        image_raw = str(row.get("imagepath", ""))
        row["resolved_path"] = _resolve_image_path(image_raw)
        out.append(row)
    return out


async def _scan_drivers_dir(client, extra_dirs: list[str]) -> list[dict]:
    """List every .sys under System32\\drivers (+ extras). Returns rows with
    absolute path + basename lowercased."""
    dirs = [r"C:\Windows\System32\drivers"] + list(extra_dirs or [])
    out: list[dict] = []
    for d in dirs:
        try:
            entries = await client.file_list_dir(d, recursive=False,
                                                  max_entries=8192)
        except Exception:
            continue
        for e in entries:
            if e.get("dir"):
                continue
            name = str(e.get("name", ""))
            if not name.lower().endswith(".sys"):
                continue
            path = str(e.get("path") or "") or f"{d}\\{name}"
            out.append({
                "path": path,
                "basename": name.lower(),
                "size": e.get("size", 0),
            })
    return out


def _index_by_basename(rows: list[dict], get_path) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in rows:
        path = get_path(r)
        if not path:
            continue
        base = PureWindowsPath(path).name.lower()
        idx.setdefault(base, []).append(r)
    return idx


# --- Entry -----------------------------------------------------------------

async def run(sdk, params: dict) -> dict:
    include_ms = bool(params.get("include_microsoft", False))
    extra_dirs = list(params.get("extra_scan_dirs") or [])
    min_severity = str(params.get("min_severity", "warning"))
    tier_order = {"info": 0, "warning": 1, "high": 2}
    min_tier = tier_order.get(min_severity, 1)

    client = sdk.mem.view("kernel").client

    services = await _enumerate_services(client)
    modules = await sdk.mods.list(pid=0, kernel=True)
    disk_files = await _scan_drivers_dir(client, extra_dirs)

    module_index = _index_by_basename(
        modules,
        lambda r: str(r.get("path") or r.get("name", "")))
    disk_index = _index_by_basename(disk_files, lambda r: r["path"])

    findings: list[dict] = []
    counts = {"orphan": 0, "phantom": 0, "uncanonical": 0,
              "duplicate": 0, "leftover": 0, "canonical_suppressed": 0}

    # Detect duplicates first (multiple services pointing at same file).
    by_path: dict[str, list[dict]] = {}
    for svc in services:
        p = svc.get("resolved_path", "")
        if not p:
            continue
        by_path.setdefault(p.lower(), []).append(svc)
    duplicates: list[list[dict]] = [group for group in by_path.values()
                                     if len(group) > 1]

    # Per-service passes.
    for svc in services:
        resolved = svc.get("resolved_path", "")
        canonical = _is_canonical(resolved) if resolved else False
        if canonical and not include_ms:
            counts["canonical_suppressed"] += 1
            continue

        anomalies: list[str] = []
        # orphan — no file on disk
        base = PureWindowsPath(resolved).name.lower() if resolved else ""
        if base and base not in disk_index:
            anomalies.append("orphan")
        # phantom — Boot/System/Auto start but not loaded
        start = svc.get("start", 4)
        if not isinstance(start, int):
            try: start = int(start)
            except Exception: start = 4
        if start <= 2 and base and base not in module_index:
            anomalies.append("phantom")
        # uncanonical — path outside canonical drivers dir
        if resolved and not canonical:
            anomalies.append("uncanonical")

        if not anomalies:
            continue

        severity = "warning" if anomalies != ["uncanonical"] else "info"
        for anom in anomalies:
            counts[anom] = counts.get(anom, 0) + 1
        if tier_order.get(severity, 0) < min_tier:
            continue
        findings.append({
            "kind": "service",
            "anomalies": anomalies,
            "service": svc.get("name"),
            "image_path": svc.get("imagepath"),
            "resolved_path": resolved,
            "start": start,
            "type": svc.get("type"),
            "canonical": canonical,
            "severity": severity,
        })

    # Duplicates — one finding per group.
    for group in duplicates:
        first = group[0].get("resolved_path", "")
        counts["duplicate"] += len(group) - 1
        findings.append({
            "kind": "duplicate",
            "anomalies": ["duplicate"],
            "path": first,
            "services": [g.get("name") for g in group],
            "severity": "warning",
        })

    # Leftover files — .sys on disk with no service pointing at it.
    for base, files in disk_index.items():
        # Does any service resolve to this basename?
        matched = False
        for svc in services:
            r = svc.get("resolved_path", "")
            if r and PureWindowsPath(r).name.lower() == base:
                matched = True
                break
        if matched:
            continue
        # Suppress canonical .sys with no registered service? These are
        # legit inbox drivers Windows may install lazily — keep at info
        # unless the analyst asked for a self-audit.
        f0 = files[0]
        canonical = _is_canonical(f0["path"])
        if canonical and not include_ms:
            counts["canonical_suppressed"] += 1
            continue
        counts["leftover"] += 1
        findings.append({
            "kind": "leftover",
            "anomalies": ["leftover"],
            "path": f0["path"],
            "size": f0.get("size"),
            "canonical": canonical,
            "severity": "info" if canonical else "warning",
        })

    # File findings that beat the min-severity threshold.
    filed = []
    for hit in findings:
        sev = hit.get("severity", "info")
        if tier_order.get(sev, 0) < min_tier:
            continue
        try:
            title = f"{sev.upper()} driver_hygiene/{','.join(hit['anomalies'])}: " \
                    f"{hit.get('resolved_path') or hit.get('path') or hit.get('service')}"
            desc = "; ".join(f"{k}={v!r}" for k, v in hit.items()
                              if k not in ("severity", "kind"))
            fid = sdk.findings.record(sev, title, desc,
                                        refs=f"drv_hyg:{hit.get('kind')}")
            import json
            sdk.findings.evidence(fid, "driver_hygiene_entry",
                                    json.dumps(hit, indent=2, default=str))
            hit["finding_id"] = fid
        except Exception as exc:
            hit["finding_id"] = f"(unfiled: {exc})"
        filed.append(hit)

    severity_out = "info" if not filed else "warning"
    return {
        "ok": True,
        "severity": severity_out,
        "summary": (f"driver_hygiene: {counts['orphan']} orphan, "
                    f"{counts['phantom']} phantom, "
                    f"{counts['uncanonical']} uncanonical, "
                    f"{counts['duplicate']} duplicate, "
                    f"{counts['leftover']} leftover"),
        "counts": counts,
        "filed": filed,
        "totals": {
            "services_scanned": len(services),
            "loaded_modules": len(modules),
            "disk_sys_files": sum(len(v) for v in disk_index.values()),
        },
        "hint": "run with include_microsoft=true for a self-audit of canonical Windows drivers",
    }
