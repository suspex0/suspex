"""Orchestrator-side suspex0-driver health probe.

Answers the "why is driver_state DRIVER_ABSENT?" question without needing an
agent rebuild. Uses only existing agent surface:

  * reg_manage — read HKLM\\SYSTEM\\CurrentControlSet\\Services\\SuspexDrv
  * file_manage list_dir / hash — inspect the .sys file if present

Returns a flat health block the LLM can branch on:

    {
      "loaded":         bool,        # driver currently loaded (from status)
      "service": {
        "registered":   bool,
        "start_type":   int|null,    # 0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled
        "start_type_decoded": str,
        "type":         int|null,    # should be 1 (SERVICE_KERNEL_DRIVER)
        "image_path":   str,         # e.g. "\\??\\C:\\suspex\\suspex_driver.sys"
        "display_name": str,
        "error_control": int|null,
      },
      "file": {
        "present":      bool,
        "path":         str,
        "sha256":       str|null,
        "size":         int|null,
      },
      "residual": {
        "kernel_log":   bool,        # C:\\Users\\Public\\Desktop\\suspex_kernel.log
        "breadcrumb":   bool,        # %ProgramData%\\suspex\\breadcrumb.bin
      },
      "verdict":        "loaded" | "service_registered_not_started"
                        | "file_present_no_service" | "absent_clean"
                        | "orphan_service" | "unknown",
      "hint":           str,
    }

Every failing probe records a `probe_errors[]` entry rather than raising.
"""
from __future__ import annotations

from typing import Any

_SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services\SuspexDrv"
_KERNEL_LOG_PATH = r"C:\Users\Public\Desktop\suspex_kernel.log"
_BREADCRUMB_PATH = r"C:\ProgramData\suspex\breadcrumb.bin"

# Common candidate paths the driver might be installed at. The Services
# key's ImagePath is authoritative when the service exists; these are only
# fallbacks for the "file present, no service" case.
_CANDIDATE_INSTALL_DIRS = (
    r"C:\suspex",
    r"C:\Program Files\suspex",
    r"C:\Program Files\Suspex",
)

_SERVICE_START_DECODED = {
    0: "SERVICE_BOOT_START",
    1: "SERVICE_SYSTEM_START",
    2: "SERVICE_AUTO_START",
    3: "SERVICE_DEMAND_START",
    4: "SERVICE_DISABLED",
}


def _resolve_image_path(raw: str) -> str:
    r"""ImagePath is usually '\??\C:\suspex\suspex_driver.sys' or
    '\SystemRoot\System32\drivers\foo.sys'. Normalize to a plain absolute
    C: path so file_manage can act on it."""
    if not raw:
        return ""
    s = raw.strip().strip('"').strip("'")
    low = s.lower()
    # NT path prefix stripping. Note: r"\..." raw strings can't end with a
    # backslash, so we spell prefixes with escaped backslashes below.
    if low.startswith("\\??\\"):
        s = s[4:]
        # Sometimes the prefix is '\??\?\' (device path form).
        if s.startswith("?\\"):
            s = s[2:]
        return s
    if low.startswith("\\systemroot\\"):
        return "C:\\Windows\\" + s[len("\\SystemRoot\\"):]
    if low.startswith("system32\\"):
        return "C:\\Windows\\" + s
    return s


async def _read_service(client, probe_errors: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"registered": False, "start_type": None,
                            "start_type_decoded": "",
                            "type": None, "image_path": "",
                            "display_name": "", "error_control": None}
    try:
        # Prefer reg_enum first — cheap way to detect service-not-registered
        # (RegOpenKeyExW returns FILE_NOT_FOUND) vs registered-but-empty.
        enum = await client.reg_enum("HKLM", _SERVICE_KEY,
                                      want_subkeys=False, want_values=True)
    except Exception as exc:
        # Service key doesn't exist → not registered.
        s = str(exc)
        if "gle=2" in s or "FILE_NOT_FOUND" in s or "not found" in s.lower():
            return out
        probe_errors.append(f"service_enum: {s}")
        return out
    out["registered"] = True

    # Enumerate the values available so we know which ones to fetch.
    value_names = {str(v.get("name", "")) for v in enum.get("values", [])}
    async def _get(name):
        try:
            # v0.17 A-3: probe reads several renderings per value (`str`
            # for ImagePath / DisplayName, `qword` for Start / Type /
            # ErrorControl) so we ask for the wide historical shape.
            return await client.reg_get("HKLM", _SERVICE_KEY, name,
                                        raw_hex=True)
        except Exception as exc:
            probe_errors.append(f"service_get({name}): {exc}")
            return None

    if "ImagePath" in value_names:
        r = await _get("ImagePath")
        if r:
            out["image_path"] = r.get("str") or r.get("hex") or ""
    if "DisplayName" in value_names:
        r = await _get("DisplayName")
        if r:
            out["display_name"] = r.get("str") or ""
    for reg_name, out_key in (("Start", "start_type"),
                               ("Type", "type"),
                               ("ErrorControl", "error_control")):
        if reg_name in value_names:
            r = await _get(reg_name)
            if r:
                v = r.get("qword")
                try:
                    out[out_key] = int(v) if v is not None else None
                except Exception:
                    out[out_key] = None
    start = out["start_type"]
    if isinstance(start, int):
        out["start_type_decoded"] = _SERVICE_START_DECODED.get(
            start, f"UNKNOWN({start})")
    return out


async def _stat_file(client, path: str, probe_errors: list[str]) -> dict[str, Any]:
    """Best-effort stat via list_dir on the parent + hash if present."""
    out: dict[str, Any] = {"present": False, "path": path,
                            "sha256": None, "size": None}
    if not path:
        return out
    import os
    parent, name = os.path.split(path)
    if not parent or not name:
        return out
    try:
        entries = await client.file_list_dir(parent, recursive=False,
                                              max_entries=2000)
    except Exception as exc:
        s = str(exc)
        if "gle=2" in s or "FILE_NOT_FOUND" in s or "not found" in s.lower() \
           or "gle=3" in s:
            return out
        probe_errors.append(f"list_dir({parent}): {s}")
        return out
    want = name.lower()
    match = None
    for e in entries:
        if e.get("dir"):
            continue
        n = str(e.get("name", ""))
        # list_dir entries carry FULL paths as `name`; match on the raw
        # value or its basename so both shapes work.
        if n.lower() == want or os.path.basename(n).lower() == want:
            match = e
            break
    if not match:
        return out
    out["present"] = True
    out["size"] = int(match.get("size", 0))
    # Hash is optional — the file may be locked while loaded; try but don't
    # treat a failure as an error worth surfacing.
    try:
        h = await client.file_hash(path)
        out["sha256"] = h.get("sha256")
    except Exception:
        pass
    return out


async def _residual(client, probe_errors: list[str]) -> dict[str, bool]:
    out = {"kernel_log": False, "breadcrumb": False}
    for path, key in ((_KERNEL_LOG_PATH, "kernel_log"),
                      (_BREADCRUMB_PATH, "breadcrumb")):
        info = await _stat_file(client, path, probe_errors)
        if info["present"]:
            out[key] = True
    return out


def _verdict(loaded: bool, svc: dict, file_info: dict) -> tuple[str, str]:
    """Return (verdict, hint) — a short label + one-line next action."""
    if loaded:
        return ("loaded",
                "driver is running — target_manage(action='status') should show driver_state=DRIVER_SERVICE")
    if svc.get("registered") and file_info.get("present"):
        return ("service_registered_not_started",
                "driver service exists and .sys is present; run "
                "target_manage(action='driver_load') to start it")
    if svc.get("registered") and not file_info.get("present"):
        return ("orphan_service",
                "service is registered but the .sys file is missing at "
                f"{svc.get('image_path', '<no image_path>')} — reinstall or "
                "unregister the stale service via target_manage(action='driver_unload')")
    if not svc.get("registered") and file_info.get("present"):
        return ("file_present_no_service",
                "the driver .sys is on disk but not registered with SCM; "
                "target_manage(action='driver_load', method='service') will register+start it")
    return ("absent_clean",
            "no service, no file — nothing to load. Deploy via scripts\\deploy_to_vm.ps1")


async def probe_suspex_driver(client, *, driver_state: str | None = None) -> dict[str, Any]:
    """Full suspex-driver health probe. `client` is a connected AgentClient.

    `driver_state` is the string from Agent.Status (if the caller already
    has it) — used to fill the `loaded` flag without a second RPC.
    """
    probe_errors: list[str] = []
    loaded = (str(driver_state or "").upper() in
              ("DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED", "LOADED"))

    svc = await _read_service(client, probe_errors)

    # File check: prefer the service's ImagePath; else scan the candidate
    # install dirs for a stray suspex_driver.sys.
    file_info: dict[str, Any] = {"present": False, "path": "",
                                  "sha256": None, "size": None}
    image_path = _resolve_image_path(svc.get("image_path", ""))
    if image_path:
        file_info = await _stat_file(client, image_path, probe_errors)
    if not file_info["present"]:
        # Fallback scan — helps the file_present_no_service case.
        for d in _CANDIDATE_INSTALL_DIRS:
            candidate = f"{d}\\suspex_driver.sys"
            info = await _stat_file(client, candidate, probe_errors)
            if info["present"]:
                file_info = info
                break

    residual = await _residual(client, probe_errors)
    verdict, hint = _verdict(loaded, svc, file_info)

    return {
        "loaded": loaded,
        "service": svc,
        "file": file_info,
        "residual": residual,
        "verdict": verdict,
        "hint": hint,
        "probe_errors": probe_errors,
    }
