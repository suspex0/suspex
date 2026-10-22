"""Target-state snapshot / diff plugin.

Captures kernel modules, running processes, per-process VAD summary,
Services + Run/RunOnce registry keys, and file hashes for a configurable
set of paths. Snapshots land under artifacts/snapshots/<label>_<iso>.json
with a <label>_latest.json pointer.

Diff mode returns per-category adds/removes/changes so an analyst can see
"did anything move between these two states" without a 200-line
PowerShell + manual Compare-Object.

Entirely read-only from the target's perspective.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --- Defaults ---------------------------------------------------------------

_DEFAULT_CATEGORIES = ("kernel_modules", "processes", "vad_summary",
                       "services", "run_keys", "file_hashes")

# System32\drivers is the canonical BYOVD staging surface; hashing it every
# snapshot means we notice new/changed .sys files without a per-file config.
_DEFAULT_FILE_GLOBS = (
    r"C:\Windows\System32\drivers\*.sys",
)

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_RUN_KEYS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


# Set by run() from sdk.artifacts_dir — the canonical artifacts root
# passed down from the orchestrator config (cwd-independent).
_ARTIFACTS_ROOT: Path | None = None


def _snapshots_dir() -> Path:
    p = (_ARTIFACTS_ROOT or Path.cwd() / "artifacts") / "snapshots"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _snapshot_path(label: str, iso: str) -> Path:
    return _snapshots_dir() / f"{label}_{iso}.json"


def _latest_path(label: str) -> Path:
    return _snapshots_dir() / f"{label}_latest.json"


def _write_snapshot(path: Path, latest: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    # Best-effort "latest" pointer. On Windows a symlink needs admin, so we
    # write a copy — small file, negligible cost.
    try:
        latest.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    except OSError:
        pass


def _load_snapshot_by_label_or_path(spec: str) -> dict:
    """Accepts a label ('pre' -> looks up _latest.json) or an absolute path."""
    if not spec:
        raise ValueError("snapshot spec is empty")
    p = Path(spec)
    if p.is_absolute() and p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    latest = _latest_path(spec)
    if latest.exists():
        return json.loads(latest.read_text(encoding="utf-8"))
    # Fall back: newest file matching label*
    hits = sorted(_snapshots_dir().glob(f"{spec}_*.json"),
                  key=lambda x: x.stat().st_mtime, reverse=True)
    if hits:
        return json.loads(hits[0].read_text(encoding="utf-8"))
    raise FileNotFoundError(f"no snapshot found for label={spec!r}")


# --- Capture helpers --------------------------------------------------------

async def _capture_kernel_modules(sdk) -> list[dict]:
    """[{name, base_hex, size_hex, path}, ...] sorted by name."""
    rows = await sdk.mods.list(pid=0, kernel=True)
    out = []
    for m in rows:
        base = m.get("base", 0)
        size = m.get("size", 0)
        base_i = int(base, 0) if isinstance(base, str) else int(base)
        size_i = int(size, 0) if isinstance(size, str) else int(size)
        out.append({
            "name": str(m.get("name", "")),
            "path": str(m.get("path", "")),
            "base": f"0x{base_i:x}",
            "size": f"0x{size_i:x}",
        })
    out.sort(key=lambda r: r["name"].lower())
    return out


async def _capture_processes(sdk) -> list[dict]:
    """[{pid, parent_pid, image_name}, ...]"""
    rows = await sdk.procs.list()
    out = [{"pid": int(p.get("pid", 0)),
            "parent_pid": int(p.get("parent_pid", 0)),
            "image_name": str(p.get("image_name", ""))} for p in rows]
    out.sort(key=lambda r: (r["image_name"].lower(), r["pid"]))
    return out


async def _capture_vad_summary(sdk, pid_include: list[int],
                                max_vad_per_process: int) -> list[dict]:
    """Per-process VAD stat rollup — cheap enough for a snapshot.

    Returns one row per pid: total VAD count, count of PAGE_EXECUTE_*, count
    of Private (no backing file). Callers who want the full VAD list should
    use mem_rw(action='vad', pid=N) directly.
    """
    kernel_view = sdk.mem.view("kernel")
    client = kernel_view.client
    procs = await sdk.procs.list()
    pids: list[int] = [int(p.get("pid", 0)) for p in procs
                        if int(p.get("pid", 0)) not in (0, 4)]
    if pid_include:
        pids = [pid for pid in pids if pid in set(pid_include)]

    out: list[dict] = []
    for pid in pids:
        try:
            entries = await client.mem_vad(pid)
        except Exception as exc:
            out.append({"pid": pid, "error": str(exc)})
            continue
        entries = entries[:max_vad_per_process]
        total = len(entries)
        rwx = 0
        exec_read = 0
        private = 0
        for e in entries:
            protect = int(e.get("protect", 0))
            vad_type = int(e.get("vad_type", 0))
            base = int(protect) & 0xFF
            if base in (0x40, 0x80):        # PAGE_EXECUTE_READWRITE / _WRITECOPY
                rwx += 1
            if base == 0x20:                # PAGE_EXECUTE_READ
                exec_read += 1
            if vad_type == 0:               # private
                private += 1
        out.append({"pid": pid, "total_vad": total, "rwx": rwx,
                    "exec_read": exec_read, "private": private})
    out.sort(key=lambda r: r["pid"])
    return out


async def _capture_services(sdk) -> list[dict]:
    """[{name, image_path, start, type, group}, ...]"""
    client = sdk.mem.view("kernel").client
    try:
        enum = await client.reg_enum("HKLM", _SERVICES_KEY,
                                      want_subkeys=True, want_values=False)
    except Exception:
        return []
    out: list[dict] = []
    for name in enum.get("subkeys", []):
        key = f"{_SERVICES_KEY}\\{name}"
        row: dict[str, Any] = {"name": name}
        for value in ("ImagePath", "Start", "Type", "Group", "ObjectName"):
            try:
                v = await client.reg_get("HKLM", key, value)
            except Exception:
                continue
            row[value.lower()] = (v.get("str") or v.get("qword")
                                   or v.get("hex") or "")
        out.append(row)
    out.sort(key=lambda r: r["name"].lower())
    return out


async def _capture_run_keys(sdk) -> list[dict]:
    """[{hive, subkey, values: {name: {type, str, qword, hex}}}, ...]"""
    client = sdk.mem.view("kernel").client
    out: list[dict] = []
    for hive, subkey in _RUN_KEYS:
        try:
            enum = await client.reg_enum(hive, subkey, want_subkeys=False,
                                          want_values=True)
        except Exception as exc:
            out.append({"hive": hive, "subkey": subkey, "error": str(exc)})
            continue
        values: dict[str, Any] = {}
        for meta in enum.get("values", []):
            vname = meta.get("name", "")
            try:
                v = await client.reg_get(hive, subkey, vname)
            except Exception:
                continue
            values[vname] = {
                "type": v.get("type"),
                "str": v.get("str") or "",
                "qword": v.get("qword") or 0,
                "hex": v.get("hex") or "",
            }
        out.append({"hive": hive, "subkey": subkey, "values": values})
    return out


async def _capture_file_hashes(sdk, globs: list[str]) -> list[dict]:
    """[{path, sha256, size}, ...] — hashes via file_manage on the target."""
    client = sdk.mem.view("kernel").client
    out: list[dict] = []
    for pattern in globs:
        # No glob expansion server-side yet, so list_dir the pattern's parent
        # and filter locally.
        parent = str(Path(pattern).parent)
        stem = Path(pattern).name
        try:
            entries = await client.file_list_dir(parent, recursive=False,
                                                  max_entries=8192)
        except Exception as exc:
            out.append({"pattern": pattern, "error": str(exc)})
            continue
        import fnmatch
        for e in entries:
            if e.get("dir"):
                continue
            path = str(e.get("path") or "")
            if not path:
                # Some agents return name only — reconstruct.
                path = str(Path(parent) / str(e.get("name", "")))
            if stem == "*" or fnmatch.fnmatch(Path(path).name.lower(),
                                                stem.lower()):
                try:
                    h = await client.file_hash(path)
                except Exception as exc:
                    out.append({"path": path, "error": str(exc)})
                    continue
                out.append({"path": path,
                            "sha256": h.get("sha256"),
                            "size": h.get("size")})
    out.sort(key=lambda r: r.get("path", ""))
    return out


# --- Diff ------------------------------------------------------------------

def _stable_key(category: str, row: dict) -> tuple:
    """Category-specific dedupe key for diff logic."""
    if category == "kernel_modules":
        return ("mod", row["name"].lower())
    if category == "processes":
        return ("proc", int(row["pid"]))
    if category == "vad_summary":
        return ("vad", int(row["pid"]))
    if category == "services":
        return ("svc", row["name"].lower())
    if category == "run_keys":
        return ("runkey", row.get("hive"), row.get("subkey"))
    if category == "file_hashes":
        return ("hash", (row.get("path") or "").lower())
    return ("misc", json.dumps(row, sort_keys=True))


def _diff_category(a: list[dict], b: list[dict], category: str) -> dict:
    a_index = {_stable_key(category, r): r for r in a}
    b_index = {_stable_key(category, r): r for r in b}
    added_keys = set(b_index) - set(a_index)
    removed_keys = set(a_index) - set(b_index)
    common_keys = set(a_index) & set(b_index)
    changed = []
    for k in common_keys:
        before = a_index[k]
        after = b_index[k]
        # Ignore volatile fields per category so diffs are quiet on reruns.
        if category == "file_hashes":
            if before.get("sha256") != after.get("sha256") or \
               before.get("size") != after.get("size"):
                changed.append({"before": before, "after": after})
        elif category == "run_keys":
            if before.get("values") != after.get("values"):
                changed.append({"before": before, "after": after})
        elif category == "vad_summary":
            for f in ("total_vad", "rwx", "exec_read", "private"):
                if before.get(f) != after.get(f):
                    changed.append({"before": before, "after": after})
                    break
        elif category == "services":
            for f in ("imagepath", "start", "type", "group"):
                if before.get(f) != after.get(f):
                    changed.append({"before": before, "after": after})
                    break
        elif category == "kernel_modules":
            if before.get("base") != after.get("base") or \
               before.get("size") != after.get("size") or \
               before.get("path") != after.get("path"):
                changed.append({"before": before, "after": after})
        elif category == "processes":
            if before.get("parent_pid") != after.get("parent_pid") or \
               before.get("image_name") != after.get("image_name"):
                changed.append({"before": before, "after": after})
    return {
        "added": [b_index[k] for k in added_keys],
        "removed": [a_index[k] for k in removed_keys],
        "changed": changed,
        "unchanged_count": len(common_keys) - len(changed),
    }


# --- Entry -----------------------------------------------------------------

async def run(sdk, params: dict) -> dict:
    global _ARTIFACTS_ROOT
    _ARTIFACTS_ROOT = Path(getattr(sdk, "artifacts_dir", "")
                            or Path.cwd() / "artifacts")
    mode = str(params.get("mode", "capture"))
    if mode == "capture":
        return await _capture(sdk, params)
    if mode == "list":
        return _list()
    if mode == "diff":
        return _diff(params)
    if mode == "show":
        return _show(params)
    if mode == "purge":
        return _purge(params)
    return {"ok": False, "severity": "info",
            "summary": f"snapshot: unknown mode {mode!r}",
            "hint": "capture | list | diff | show | purge"}


async def _capture(sdk, params: dict) -> dict:
    categories = tuple(params.get("categories") or _DEFAULT_CATEGORIES)
    label = str(params.get("label") or "auto")
    if label == "auto":
        label = "snapshot"
    file_globs = list(params.get("file_globs") or _DEFAULT_FILE_GLOBS)
    pid_include = [int(p) for p in (params.get("pid_include") or [])]
    max_vad = int(params.get("max_vad_per_process", 256))

    started = time.time()
    data: dict[str, Any] = {
        "schema_version": 1,
        "label": label,
        "captured_at": _now_iso(),
        "categories": list(categories),
    }

    try:
        status = await sdk.mem.view("kernel").client.status()
        data["target"] = {
            "computer": status.get("os_version", ""),
            "os_build": status.get("os_build", 0),
            "driver_state": status.get("driver_state", ""),
            "agent_version": status.get("agent_version", ""),
            "hvci": status.get("hvci", False),
        }
    except Exception as exc:
        data["target_error"] = str(exc)

    if "kernel_modules" in categories:
        data["kernel_modules"] = await _capture_kernel_modules(sdk)
    if "processes" in categories:
        data["processes"] = await _capture_processes(sdk)
    if "vad_summary" in categories:
        data["vad_summary"] = await _capture_vad_summary(sdk, pid_include, max_vad)
    if "services" in categories:
        data["services"] = await _capture_services(sdk)
    if "run_keys" in categories:
        data["run_keys"] = await _capture_run_keys(sdk)
    if "file_hashes" in categories:
        data["file_hashes"] = await _capture_file_hashes(sdk, file_globs)

    iso = _now_iso()
    path = _snapshot_path(label, iso)
    latest = _latest_path(label)
    _write_snapshot(path, latest, data)

    duration = round(time.time() - started, 2)
    counts = {c: len(data.get(c, [])) for c in categories}

    return {
        "ok": True,
        "severity": "info",
        "summary": (f"snapshot '{label}' captured in {duration}s — "
                    + ", ".join(f"{c}={n}" for c, n in counts.items())),
        "mode": "capture",
        "label": label,
        "path": str(path),
        "latest_path": str(latest),
        "duration_s": duration,
        "counts": counts,
        "target": data.get("target", {}),
    }


def _list() -> dict:
    d = _snapshots_dir()
    rows = []
    for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        rows.append({
            "path": str(p),
            "size_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        })
    return {"ok": True, "severity": "info", "mode": "list",
            "summary": f"{len(rows)} snapshot files under {d}",
            "snapshots": rows, "root": str(d)}


def _show(params: dict) -> dict:
    label = str(params.get("label") or "")
    if not label:
        return {"ok": False, "severity": "info", "mode": "show",
                "summary": "show: label required"}
    try:
        data = _load_snapshot_by_label_or_path(label)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "severity": "info", "mode": "show",
                "summary": str(exc)}
    counts = {c: len(data.get(c, [])) for c in data.get("categories", [])
              if isinstance(data.get(c), list)}
    return {"ok": True, "severity": "info", "mode": "show",
            "summary": f"snapshot label={label} captured={data.get('captured_at')}",
            "label": data.get("label"),
            "captured_at": data.get("captured_at"),
            "categories": data.get("categories", []),
            "counts": counts,
            "target": data.get("target", {}),
            "data": data}


def _diff(params: dict) -> dict:
    a_spec = str(params.get("label") or "")
    b_spec = str(params.get("compare_to") or "")
    if not a_spec or not b_spec:
        return {"ok": False, "severity": "info", "mode": "diff",
                "summary": "diff: needs both label and compare_to"}
    try:
        a = _load_snapshot_by_label_or_path(a_spec)
        b = _load_snapshot_by_label_or_path(b_spec)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "severity": "info", "mode": "diff",
                "summary": str(exc)}

    categories = tuple(params.get("categories")
                        or a.get("categories")
                        or _DEFAULT_CATEGORIES)
    result: dict[str, Any] = {}
    total_added = 0
    total_removed = 0
    total_changed = 0
    for cat in categories:
        a_rows = a.get(cat) or []
        b_rows = b.get(cat) or []
        d = _diff_category(a_rows, b_rows, cat)
        result[cat] = d
        total_added += len(d["added"])
        total_removed += len(d["removed"])
        total_changed += len(d["changed"])

    severity = "info"
    if total_added or total_removed or total_changed:
        severity = "warning"

    return {
        "ok": True, "severity": severity, "mode": "diff",
        "summary": (f"diff {a_spec} → {b_spec}: "
                    f"+{total_added} -{total_removed} ~{total_changed}"),
        "a_label": a.get("label"),
        "a_captured_at": a.get("captured_at"),
        "b_label": b.get("label"),
        "b_captured_at": b.get("captured_at"),
        "categories": list(categories),
        "totals": {"added": total_added, "removed": total_removed,
                   "changed": total_changed},
        "diff": result,
    }


def _purge(params: dict) -> dict:
    days = int(params.get("purge_older_than_days", 30))
    if days < 1:
        return {"ok": False, "severity": "info", "mode": "purge",
                "summary": "purge_older_than_days must be >= 1"}
    cutoff = time.time() - days * 86400
    removed = []
    for p in _snapshots_dir().glob("*.json"):
        if p.name.endswith("_latest.json"):
            continue
        if p.stat().st_mtime < cutoff:
            try:
                p.unlink()
                removed.append(str(p))
            except OSError:
                pass
    return {"ok": True, "severity": "info", "mode": "purge",
            "summary": f"purged {len(removed)} snapshots older than {days} days",
            "removed": removed}
