"""exec_ghidra_script — the arbitrary-Python escape hatch, counterpart
of suspex_idalib_ext's exec_idapython.

Runs caller Python inside the backend process with ``program``, ``flat``,
``project`` and a pre-bound ``to_addr``/``monitor`` in scope, captures
stdout/stderr, and surfaces a ``result`` local when the script sets one.
"""
from __future__ import annotations

import contextlib
import io
import json
from typing import Any

from .state import STATE, _j

_EXEC_RESULT_CAP_BYTES = 64 * 1024


def _coerce_json_safe(obj: Any, _depth: int = 0) -> Any:
    if _depth > 6:
        return str(obj)
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _coerce_json_safe(v, _depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_coerce_json_safe(v, _depth + 1) for v in obj]
    # JPype objects / Java types -> readable repr
    return str(obj)


def exec_ghidra_script(binary_name: str, source: str = "",
                       code: str = "", script: str = "") -> str:
    """Run Python inside the backend JVM process.

    Scope: ``program`` (resolved binary_name), ``flat`` (FlatProgramAPI),
    ``project``, ``STATE``, ``to_addr(x)``, ``monitor`` — plus a
    ``jpype`` and ``ghidra`` package handle for direct class access.
    Set a ``result`` local to have it JSON-returned; stdout/stderr are
    captured either way.
    """
    st = STATE.get(binary_name)
    src = source or code or script
    if not src:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "source/code/script is required"})
    program = st["program"]
    env: dict[str, Any] = {
        "program": program,
        "currentProgram": program,      # GhidraScript convention
        "flat": st["flat"],
        "project": STATE.project,
        "STATE": STATE,
        "to_addr": lambda v: STATE.to_addr(program, v),
        "monitor": STATE.monitor(),
        "json": json,
    }
    try:
        import jpype  # noqa: F401
        env["jpype"] = jpype
        env["JClass"] = jpype.JClass
    except ImportError:
        pass
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with STATE.lock, contextlib.redirect_stdout(stdout_buf), \
            contextlib.redirect_stderr(stderr_buf):
        try:
            exec(compile(src, "<exec_ghidra_script>", "exec"), env)
        except Exception as exc:  # noqa: BLE001
            return _j({
                "ok": False, "kind": "script_error",
                "error": f"{type(exc).__name__}: {exc}",
                "stdout": stdout_buf.getvalue()[-8192:],
                "stderr": stderr_buf.getvalue()[-8192:],
            })
    out: dict[str, Any] = {
        "ok": True,
        "stdout": stdout_buf.getvalue()[-8192:],
        "stderr": stderr_buf.getvalue()[-8192:],
    }
    if "result" in env:
        try:
            res = _coerce_json_safe(env["result"])
            text = json.dumps(res)
            if len(text) > _EXEC_RESULT_CAP_BYTES:
                res = (f"<result truncated at "
                       f"{_EXEC_RESULT_CAP_BYTES} bytes>")
            out["result"] = res
        except Exception as exc:  # noqa: BLE001
            out["result_error"] = f"unserializable result: {exc}"
    return _j(out)
