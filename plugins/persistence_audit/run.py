"""Windows persistence-surface audit.

Enumerates Run/RunOnce keys (HKLM + HKCU + WOW64), Services (Type 0x1|0x2
with Start <= 3), Winlogon shell/userinit, Image File Execution Options
debuggers, and AppInit_DLLs. For every entry, extracts the on-disk path
it will execute (from the value or ImagePath), classifies as "microsoft
canonical" or "third-party / unusual", and files per-entry findings above
`min_severity`.

Purely read-only from the target's perspective; the classifier is entirely
path-based (no signature check) — that's for a follow-up (`driver_hygiene`
already touches signer analysis for the kernel driver surface).
"""
from __future__ import annotations

import re
from typing import Any

# --- Config ----------------------------------------------------------------

_DEFAULT_CATEGORIES = ("run_keys", "services", "winlogon", "ifeo", "appinit")

_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_APPINIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

# Windows canonical prefixes — anything under here + a valid-looking name is
# almost never a persistence surprise. Case-insensitive.
_CANONICAL_PATH_PREFIXES = (
    r"c:\windows\system32\\",
    r"c:\windows\syswow64\\",
    r"c:\windows\servicing\\",
    r"c:\program files\windowsapps\\",
    r"c:\programdata\microsoft\\",
)


def _looks_canonical(path: str) -> bool:
    p = path.lower().strip().strip('"').strip("'")
    for pref in _CANONICAL_PATH_PREFIXES:
        if p.startswith(pref):
            return True
    return False


def _resolve_command_target(cmd: str) -> str:
    """Given a raw command string ("\"C:\\path.exe\" -flag arg"), return the
    executable path (dequoted, first token)."""
    cmd = cmd.strip()
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end != -1 else cmd[1:]
    return cmd.split(None, 1)[0]


def _tier_for(canonical: bool) -> tuple[str, str]:
    if canonical:
        return "info", "canonical (System32/SysWOW64/Servicing)"
    return "warning", "path outside canonical Windows locations"


# --- Category walkers ------------------------------------------------------

async def _walk_run_keys(client) -> list[dict]:
    out: list[dict] = []
    for hive, subkey in _RUN_KEYS:
        try:
            enum = await client.reg_enum(hive, subkey,
                                          want_subkeys=False, want_values=True)
        except Exception:
            continue
        for meta in enum.get("values", []):
            vname = meta.get("name", "")
            try:
                v = await client.reg_get(hive, subkey, vname)
            except Exception:
                continue
            cmd = v.get("str") or ""
            target = _resolve_command_target(cmd)
            canonical = _looks_canonical(target)
            out.append({
                "category": "run_keys",
                "hive": hive, "subkey": subkey, "value": vname,
                "command": cmd, "target": target,
                "canonical": canonical,
            })
    return out


async def _walk_services(client) -> list[dict]:
    try:
        enum = await client.reg_enum("HKLM", _SERVICES_KEY,
                                      want_subkeys=True, want_values=False)
    except Exception:
        return []
    out: list[dict] = []
    for name in enum.get("subkeys", []):
        key = f"{_SERVICES_KEY}\\{name}"
        row: dict[str, Any] = {"category": "services", "name": name,
                                "subkey": key}
        for value in ("ImagePath", "Start", "Type", "Group", "ObjectName",
                      "DisplayName"):
            try:
                v = await client.reg_get("HKLM", key, value)
            except Exception:
                continue
            row[value.lower()] = (v.get("str") or v.get("qword")
                                   or v.get("hex") or "")
        start = row.get("start", 4)
        svc_type = row.get("type", 0)
        if not isinstance(start, int):
            try: start = int(start)
            except Exception: start = 4
        if not isinstance(svc_type, int):
            try: svc_type = int(svc_type)
            except Exception: svc_type = 0
        # Filter down to kernel/user services with Start <= 3 (Boot/System/Auto/Manual)
        if not (svc_type & 0xFF) in (0x001, 0x002, 0x010, 0x020, 0x050, 0x060):
            continue
        if start >= 4:  # disabled
            continue
        image = str(row.get("imagepath", ""))
        target = _resolve_command_target(image)
        row["target"] = target
        row["canonical"] = _looks_canonical(target)
        out.append(row)
    return out


async def _walk_winlogon(client) -> list[dict]:
    out: list[dict] = []
    for value in ("Shell", "Userinit", "Taskman", "System", "GinaDLL"):
        try:
            v = await client.reg_get("HKLM", _WINLOGON_KEY, value)
        except Exception:
            continue
        cmd = v.get("str") or ""
        if not cmd:
            continue
        target = _resolve_command_target(cmd)
        out.append({
            "category": "winlogon", "hive": "HKLM", "subkey": _WINLOGON_KEY,
            "value": value, "command": cmd, "target": target,
            "canonical": _looks_canonical(target),
        })
    return out


async def _walk_ifeo(client) -> list[dict]:
    try:
        enum = await client.reg_enum("HKLM", _IFEO_KEY,
                                      want_subkeys=True, want_values=False)
    except Exception:
        return []
    out: list[dict] = []
    for name in enum.get("subkeys", []):
        try:
            v = await client.reg_get("HKLM", f"{_IFEO_KEY}\\{name}", "Debugger")
        except Exception:
            continue
        cmd = v.get("str") or ""
        if not cmd:
            continue
        target = _resolve_command_target(cmd)
        out.append({
            "category": "ifeo", "target_image": name,
            "hive": "HKLM", "subkey": f"{_IFEO_KEY}\\{name}",
            "value": "Debugger", "command": cmd, "target": target,
            "canonical": _looks_canonical(target),
        })
    return out


async def _walk_appinit(client) -> list[dict]:
    out: list[dict] = []
    for value in ("AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs"):
        try:
            v = await client.reg_get("HKLM", _APPINIT_KEY, value)
        except Exception:
            continue
        content = v.get("str") or v.get("qword") or ""
        if not content:
            continue
        out.append({
            "category": "appinit", "hive": "HKLM", "subkey": _APPINIT_KEY,
            "value": value, "command": str(content),
            # AppInit_DLLs is dangerous by existence, not by target — no
            # canonical-path pass here.
            "canonical": False,
        })
    return out


# --- Entry -----------------------------------------------------------------

async def run(sdk, params: dict) -> dict:
    categories = tuple(params.get("categories") or _DEFAULT_CATEGORIES)
    include_microsoft = bool(params.get("include_microsoft", False))
    min_severity = str(params.get("min_severity", "warning"))
    tier_order = {"info": 0, "warning": 1, "high": 2}
    min_tier = tier_order.get(min_severity, 1)

    client = sdk.mem.view("kernel").client

    rows: list[dict] = []
    if "run_keys" in categories:
        rows.extend(await _walk_run_keys(client))
    if "services" in categories:
        rows.extend(await _walk_services(client))
    if "winlogon" in categories:
        rows.extend(await _walk_winlogon(client))
    if "ifeo" in categories:
        rows.extend(await _walk_ifeo(client))
    if "appinit" in categories:
        rows.extend(await _walk_appinit(client))

    filed: list[dict] = []
    counts = {"total": len(rows), "canonical_suppressed": 0,
              "info": 0, "warning": 0, "high": 0}

    for row in rows:
        canonical = row.get("canonical", False)
        if canonical and not include_microsoft:
            counts["canonical_suppressed"] += 1
            continue
        severity = "warning" if not canonical else "info"
        if row.get("category") == "appinit":
            severity = "high"       # AppInit_DLLs enabled at all is noteworthy
        counts[severity] = counts.get(severity, 0) + 1
        if tier_order.get(severity, 0) < min_tier:
            continue
        ref = _ref_for(row)
        title = _title_for(row, severity)
        desc = _description_for(row)
        try:
            fid = sdk.findings.record(severity, title, desc, refs=ref)
            sdk.findings.evidence(fid, "persistence_entry",
                                    _evidence_blob(row))
        except Exception as exc:
            fid = f"(unfiled: {exc})"
        filed.append({"category": row.get("category"),
                       "target": row.get("target"),
                       "severity": severity,
                       "canonical": canonical,
                       "finding_id": fid})

    severity_out = "info" if counts["warning"] + counts["high"] == 0 else "warning"
    return {
        "ok": True, "severity": severity_out,
        "summary": (f"persistence_audit: {counts['warning']} warning, "
                    f"{counts['high']} high, {counts['canonical_suppressed']} "
                    "canonical suppressed"),
        "mode": "audit",
        "categories": list(categories),
        "counts": counts,
        "filed": filed,
        "hint": "run with include_microsoft=true for a self-audit of canonical entries; "
                "raw rows are in each finding's evidence blob",
    }


def _ref_for(row: dict) -> str:
    cat = row.get("category", "misc")
    sub = row.get("subkey") or row.get("hive", "") + "\\" + row.get("value", "")
    return f"persist:{cat}:{sub}"


def _title_for(row: dict, severity: str) -> str:
    cat = row.get("category")
    tgt = row.get("target") or row.get("command", "")
    return f"{severity.upper()} persist/{cat}: {tgt}"


def _description_for(row: dict) -> str:
    cat = row.get("category")
    parts = [f"category={cat}"]
    for k in ("hive", "subkey", "value", "target", "target_image",
              "command", "start", "type", "displayname"):
        if row.get(k) is not None:
            parts.append(f"{k}={row.get(k)!r}")
    return "; ".join(parts)


def _evidence_blob(row: dict) -> str:
    import json
    return json.dumps(row, indent=2, default=str)
