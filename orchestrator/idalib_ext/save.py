"""Save-safety patches + periodic checkpointing + exec_idapython.

Hosts the input-path record hook (``_record_input_path``), the
autoanalysis env gate (``_patch_no_auto``), and the always-on
save-target guard (``_patch_safe_save``) that redirects any
``save_database`` back onto ``<input>.i64``. ``idb_save`` is the
external tool, ``_spawn_periodic_saver`` is its background sibling.

``exec_idapython`` lives here so it can share the ``_INPUT_PATH_FOR_SAVE``
module-level with the save helpers; it uses :func:`~idalib_ext.funcs._coerce_json_safe`
for the native-JSON result wrapping introduced by v0.17 D-5.
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
from typing import Annotated, Any

import ida_pro_mcp.idalib_server as _core

from .funcs import _EXEC_RESULT_CAP_BYTES, _coerce_json_safe  # noqa: F401 - re-exported for monkeypatch parity


def exec_idapython(
    source: Annotated[str, "IDAPython source. Assign to `result` to return a value."],
) -> dict:
    """Run arbitrary IDAPython inside the analyst session.

    Captures stdout+stderr. If the script sets a local named ``result``,
    it comes back as a native JSON value (dict, list, int, str, bytes-as-hex,
    …) so callers no longer have to parse ``repr(...)`` on the far side.
    Use for one-off tasks (mass-rename, custom xref walks, struct
    extraction) — anything that would otherwise mean opening GUI IDA.

    Response fields (v0.17 D-5):
      * ``result``        native value when JSON round-trips; ``repr``
                          fallback string when it doesn't. ``None`` when the
                          script never assigned ``result``.
      * ``result_native`` ``True`` when ``result`` is a JSON-native value
                          (dict/list/…); ``False`` when it's a ``repr``
                          fallback. Absent when ``result`` is ``None``.
      * ``result_type``   Python type name of the pre-coercion value
                          (``"dict"``, ``"bytes"``, ``"NoneType"``, …).
      * ``result_truncated`` present as ``True`` only when the native form
                          exceeded the 1 MiB response cap and we fell back
                          to a bounded ``repr``.

    Safety: same privileges as the shim; treat ``source`` like a shell
    command. No workspace sandbox — a bad script can trash the IDB.
    """
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    ns: dict[str, Any] = {"__name__": "__main__"}
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        try:
            exec(compile(source, "<exec_idapython>", "exec"), ns)
        except BaseException as exc:  # noqa: BLE001 - reflect all script errors
            return {"ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "stdout": buf_out.getvalue(),
                    "stderr": buf_err.getvalue()}
    result = ns.get("result")
    out: dict[str, Any] = {"ok": True,
                           "stdout": buf_out.getvalue(),
                           "stderr": buf_err.getvalue(),
                           "result_type": type(result).__name__}
    if result is None:
        out["result"] = None
    else:
        safe, native, truncated = _coerce_json_safe(result)
        out["result"] = safe
        out["result_native"] = native
        if truncated:
            out["result_truncated"] = True
    return out


_INPUT_PATH_FOR_SAVE: str = ""


def _safe_save_target(explicit: str | None = None) -> tuple[str, str | None]:
    """Return (target_path, warning). Refuses to save on top of the
    input binary — that overwrites the .sys with IDA2-magic bytes and
    destroys the input (real bug hit during the EDID engagement).
    Rule: if the target equals the input path (case-insensitive), OR
    lacks a database extension (.i64/.idb/.i32/.i5), redirect to
    `<input>.i64`.
    """
    from pathlib import Path as _P
    inp = _INPUT_PATH_FOR_SAVE
    default_target = inp + ".i64" if inp else ""
    if explicit:
        t = str(_P(explicit).resolve())
        if inp and t.lower() == str(_P(inp).resolve()).lower():
            return default_target, ("save_target equals input; redirected to "
                                    f"{default_target}")
        low = t.lower()
        if not (low.endswith(".i64") or low.endswith(".idb")
                or low.endswith(".i32") or low.endswith(".i5")):
            return default_target, (f"save_target {t!r} lacks a database "
                                    f"extension; redirected to {default_target}")
        return t, None
    if not default_target:
        return "", "no input path recorded; cannot pick a safe default"
    return default_target, None


def idb_save(
    reason: Annotated[str, "Free-text tag for the save event (shown in the log)"] = "",
    target: Annotated[str, "Optional save path; empty = <input>.i64. NEVER equals the input file."] = "",
) -> dict:
    """Force-checkpoint the current IDB to disk NOW.

    Safety: refuses (or redirects) any target that would overwrite the
    original input binary — a `save_database(input.sys)` writes packed
    IDA2 bytes over the .sys and destroys it. Default target is
    `<input>.i64`.

    Use before running a batch of destructive `exec_idapython` scripts,
    or right before a long autoanalysis pass — a shim/backend crash
    otherwise loses 20-40 min of work. Also called by the background
    periodic-save thread every `SUSPX_IDA_SAVE_EVERY_S` seconds
    (default 120).
    """
    import idapro
    import ida_auto
    state = ida_auto.get_auto_state()
    if state != ida_auto.AU_NONE:
        return {"ok": False, "state": int(state), "reason": reason,
                "error": "autoanalysis is inside a segment change "
                         "(state != AU_NONE); retry when idle"}
    path, warn = _safe_save_target(target or None)
    if not path:
        return {"ok": False, "reason": reason, "error": warn or "no target"}
    try:
        idapro.save_database(path)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": reason, "target": path,
                "error": f"{type(exc).__name__}: {exc}"}
    out = {"ok": True, "reason": reason, "state": int(state), "target": path}
    if warn:
        out["warning"] = warn
    return out


def _spawn_periodic_saver() -> None:
    """Background thread: `save_database(<input>.i64)` every
    SUSPX_IDA_SAVE_EVERY_S seconds. Skips ticks where autoanalysis
    isn't idle. Bailout on any single failure — the log tells the
    operator; a follow-up open picks up the last good save.

    The target is ALWAYS `<input>.i64`, never the input file itself.
    """
    interval_s = int(os.environ.get("SUSPX_IDA_SAVE_EVERY_S", "120") or "120")
    if interval_s <= 0:
        return
    import threading
    import time as _time

    def _loop() -> None:
        import idapro
        import ida_auto
        while True:
            _time.sleep(interval_s)
            state = ida_auto.get_auto_state()
            if state != ida_auto.AU_NONE:
                continue
            path, warn = _safe_save_target(None)
            if not path:
                return
            try:
                idapro.save_database(path)
            except Exception:  # noqa: BLE001
                return

    t = threading.Thread(target=_loop, name="suspx-idb-saver", daemon=True)
    t.start()


def _patch_safe_save() -> None:
    """Last-line guard on idapro.save_database itself.

    idb_save and the periodic saver route through _safe_save_target, but
    any OTHER call site — a hook script, vanilla-server internals, an
    exec_idapython escape hatch — still reaches the raw function, and
    save_database(<input>) overwrites the input binary with packed IDA2
    bytes (destroyed a .sys mid-analysis once already). Patch the module
    attribute so EVERY save lands on a database path:
      * target == input (resolved, case-insensitive) -> <input>.i64
      * target without a database extension          -> <input>.i64
      * empty/None target                            -> <input>.i64
    Hard-refuses only when no input path is recorded (nothing safe to
    redirect to). Redirects are logged to stderr (captured in the
    backend log at %TEMP%\\suspex_idalib_<sid>.log).
    """
    idapro = _core.idapro
    try:
        orig = idapro.save_database
    except AttributeError:
        # idalib's idapro module only gains save_database after a database
        # is opened; without it there is nothing to patch. The idb_save
        # tool's own safe-target guard still covers the tool path.
        print("[suspx-guard] idapro.save_database not present yet; "
              "global guard skipped", file=sys.stderr, flush=True)
        return

    def _save(path: str | None = None, *args: Any, **kwargs: Any):
        safe, warn = _safe_save_target(path if path else None)
        if not safe:
            raise RuntimeError(
                "suspx save_database guard: refusing to save — no input "
                "path recorded and no safe database target given")
        if warn:
            print(f"[suspx-guard] save_database redirected: {warn}",
                  file=sys.stderr, flush=True)
        return orig(safe, *args, **kwargs)

    idapro.save_database = _save


def _record_input_path() -> None:
    """Patch idapro.open_database to remember the input path for our
    safe-save-target logic. Runs BEFORE _patch_no_auto's wrapper so
    the two decorators chain cleanly."""
    idapro = _core.idapro
    orig = idapro.open_database

    def _wrap(path: str, run_auto_analysis: bool = True):
        global _INPUT_PATH_FOR_SAVE
        _INPUT_PATH_FOR_SAVE = str(path)
        return orig(path, run_auto_analysis=run_auto_analysis)

    idapro.open_database = _wrap


def _patch_no_auto() -> None:
    """Env-gate: `SUSPX_IDA_NO_AUTO=1` makes open_database skip autoanalysis.
    Speeds bring-up on huge drivers when the caller wants to control
    analysis manually (add_func on specific eas, then auto_wait)."""
    idapro = _core.idapro
    orig = idapro.open_database

    def _open(path: str, run_auto_analysis: bool = True) -> Any:
        if os.environ.get("SUSPX_IDA_NO_AUTO") == "1":
            run_auto_analysis = False
        return orig(path, run_auto_analysis=run_auto_analysis)

    idapro.open_database = _open
