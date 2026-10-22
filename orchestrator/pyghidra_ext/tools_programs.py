"""Project-level tool bodies: import/list/metadata/delete/save.

These answer the shim's session-management verbs — a "session" is a
program inside the shared Ghidra project, so `open` maps to
``import_binary`` + optional analyze, and `close` maps to release+save
(or ``delete_project_binary`` on purge).
"""
from __future__ import annotations

from typing import Any

from .helpers import _addr_str, _err
from .state import STATE, _j


def import_binary(binary_path: str, name: str = "",
                  analyze: bool = True) -> str:
    """Import a binary into the shared project. ``analyze=false``
    registers the program without running auto-analysis (the caller
    runs create_function / analysis later — huge-driver workflow)."""
    out = STATE.import_binary(binary_path, name=name, analyze=analyze)
    return _j(out)


def analyze_program(binary_name: str) -> str:
    STATE.analyze(binary_name)
    # persist the analysis results — headless Ghidra never auto-saves
    STATE._save_program(binary_name)
    return _j({"ok": True, "binary_name": binary_name,
               "analyzing": STATE.is_analyzing(binary_name)})


def list_project_binaries() -> str:
    return _j({"binaries": STATE.list_programs(),
               "project": STATE.project_name,
               "project_dir": str(STATE.project_dir or "")})


def list_project_binary_metadata(binary_name: str) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    fm = p.getFunctionManager()
    return _j({
        "binary_name": binary_name,
        "path": st.get("path", ""),
        "size_on_disk": STATE._safe(
            lambda: int(__import__("os").path.getsize(st["path"]))
            if st.get("path") else 0),
        "image_base": _addr_str(p.getImageBase()),
        "min_address": _addr_str(p.getMinAddress()),
        "max_address": _addr_str(p.getMaxAddress()),
        "language": str(p.getLanguageID()),
        "compiler_spec": STATE._safe(
            lambda: str(p.getCompilerSpec().getCompilerSpecID())),
        "executable_format": STATE._safe(
            lambda: str(p.getExecutableFormat())),
        "executable_path": STATE._safe(
            lambda: str(p.getExecutablePath())),
        "function_count": int(fm.getFunctionCount()),
        "analyzing": STATE.is_analyzing(binary_name),
        "imported_at": st.get("imported_at"),
    })


def program_save(binary_name: str) -> str:
    """Checkpoint a program into the project (Ghidra does not auto-save)."""
    st = STATE.get(binary_name)
    with STATE.lock:
        try:
            df = st.get("df") or st["program"].getDomainFile()
            df.save(STATE.monitor())
            return _j({"ok": True, "binary_name": binary_name,
                       "saved": True})
        except Exception as exc:  # noqa: BLE001
            try:
                STATE.project.save(st["program"])
                return _j({"ok": True, "binary_name": binary_name,
                           "saved": True})
            except Exception as exc2:  # noqa: BLE001
                return _j(_err("save_failed",
                               f"{type(exc).__name__}: {exc}; "
                               f"project.save: {exc2}"))


def release_program(binary_name: str, save: bool = True) -> str:
    """Session-close: save + drop the registry entry; the program stays
    in the project (reopenable by name later)."""
    st = STATE.get(binary_name)
    if save:
        program_save(binary_name)
    prog = st["program"]
    with STATE.lock:
        try:
            prog.release(STATE.project)
        except Exception:  # noqa: BLE001
            try:
                prog.release()
            except Exception:  # noqa: BLE001
                pass
    STATE.programs.pop(binary_name, None)
    STATE._decomp.pop(binary_name, None)
    return _j({"ok": True, "closed": binary_name, "saved": bool(save)})


def delete_project_binary(binary_name: str) -> str:
    """Purge: release + delete the domain file from the project."""
    st = STATE.get(binary_name)
    try:
        prog = st["program"]
        prog.release(STATE.project)
    except Exception:  # noqa: BLE001
        pass
    STATE.programs.pop(binary_name, None)
    STATE._decomp.pop(binary_name, None)
    with STATE.lock:
        try:
            df = st.get("df")
            if df is not None:
                df.delete()
                return _j({"ok": True, "deleted": binary_name})
            root = STATE.project.getProjectData().getRootFolder()
            f = root.getFile(binary_name)
            if f is not None:
                f.delete()
                return _j({"ok": True, "deleted": binary_name})
            return _j(_err("not_found",
                           f"no domain file for {binary_name!r}"))
        except Exception as exc:  # noqa: BLE001
            return _j(_err("delete_failed", f"{type(exc).__name__}: {exc}"))


def project_info() -> str:
    return _j({
        "project": STATE.project_name,
        "project_dir": str(STATE.project_dir or ""),
        "programs_registered": sorted(STATE.programs),
        "jvm_started": STATE.jvm_started,
    })
