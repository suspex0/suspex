"""Backend-process helpers: how the shim spawns and env-wires the
``suspex_pyghidra_ext`` child that hosts the JVM + shared project.

Unlike ``idalib_shim.backend`` (one backend per binary), there is ONE
backend for the whole project — ``_ensure_backend`` lazily spawns it,
``BACKEND`` holds the single handle.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

from .logging import _log


# Startup readiness knobs — JVM boot + project open is slower than an
# idalib backend spawn; give it a generous ceiling.
READY_TIMEOUT_S = float(os.environ.get("SUSPX_GHIDRA_READY_S", "300"))
POLL_INTERVAL_S = 0.8


def _backend_python() -> str:
    """Interpreter for the backend child.

    Resolution order:
      1. ``SUSPX_GHIDRA_BACKEND_PYTHON`` env (explicit override)
      2. ``<orchestrator>/.ghidra-venv`` convention (mirrors
         ``.ida-mcp-venv``; ``SUSPX_GHIDRA_VENV`` may point elsewhere)
      3. ``sys.executable`` — works whenever pyghidra is installed into
         the same env as the shim (``uv sync --extra ghidra``).
    """
    override = os.environ.get("SUSPX_GHIDRA_BACKEND_PYTHON", "")
    if override and Path(override).is_file():
        return override
    orchestrator_dir = Path(__file__).resolve().parent.parent
    venv_roots = []
    env_venv = os.environ.get("SUSPX_GHIDRA_VENV", "")
    if env_venv:
        venv_roots.append(Path(env_venv))
    venv_roots.append(orchestrator_dir / ".ghidra-venv")
    for root in venv_roots:
        for cand in (root / "Scripts" / "python.exe",
                     root / "bin" / "python",
                     root / "bin" / "python3"):
            if cand.is_file():
                return str(cand)
    return sys.executable


def _backend_cmd(port: int) -> list[str]:
    """``python suspex_pyghidra_ext.py --port N --project-dir D ...``"""
    ext = Path(__file__).resolve().parent.parent / "suspex_pyghidra_ext.py"
    project_dir = os.environ.get(
        "SUSPX_GHIDRA_PROJECT_DIR",
        str(Path(__file__).resolve().parent.parent.parent
            / "artifacts" / "ghidra_project"))
    cmd = [_backend_python(),
           str(ext),
           "--port", str(port),
           "--project-dir", project_dir,
           "--project-name",
           os.environ.get("SUSPX_GHIDRA_PROJECT_NAME", "suspex")]
    heap = os.environ.get("SUSPX_GHIDRA_HEAP_MB", "")
    if heap:
        cmd += ["--heap-mb", heap]
    return cmd


def _backend_env() -> dict:
    """Child env: pass through everything plus the ghidra-specific knobs
    the bridge stamped into the shim's env."""
    env = dict(os.environ)
    if os.environ.get("SUSPX_GHIDRA_DIR"):
        env["GHIDRA_INSTALL_DIR"] = os.environ["SUSPX_GHIDRA_DIR"]
    if os.environ.get("SUSPX_GHIDRA_JAVA_HOME"):
        env["JAVA_HOME"] = os.environ["SUSPX_GHIDRA_JAVA_HOME"]
    # Backend exits when this shim process dies (shim killed without
    # cleanup) — keeps the project lock from being orphaned. The
    # backend watches our PID; stdin-PIPE EOF is unreliable through
    # uv-venv redirector launchers (they re-inherit handles).
    env["SUSPX_GHIDRA_STDIN_WATCH"] = "1"
    env["SUSPX_GHIDRA_PARENT_PID"] = str(os.getpid())
    return env


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _backend_names() -> list[str]:
    """Tool names the backend registers, sampled from the registry.

    Runs in a throwaway subprocess under the BACKEND interpreter (not
    the shim's): the tool-registry build imports mcp.server etc., which
    the backend venv has; the shim env may run a different mcp version.
    ``pyghidra_ext`` itself imports no JVM bits at module level, so the
    sample doesn't need Ghidra installed — it degrades to [] when the
    backend env is broken, and _maybe_populate_schemas fills the real
    list on first live connection.
    """
    snippet = (
        "import json, sys; "
        "sys.path.insert(0, %r); "
        "from pyghidra_ext.server import _build_registry; "
        "print('RESULT:' + json.dumps(sorted(_build_registry())))"
        % str(Path(__file__).resolve().parent.parent)
    )
    try:
        import subprocess as _sp
        proc = _sp.run(
            [_backend_python(), "-c", snippet], capture_output=True,
            text=True, encoding="utf-8", timeout=60, check=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT:"):
                return json.loads(line[len("RESULT:"):])
        raise ValueError("no RESULT: line in subprocess output")
    except Exception as exc:  # noqa: BLE001 - inventory is best-effort
        _log(f"shim: backend tool inventory unavailable: {exc}")
        return []


def _dump_startup_env() -> None:
    """Dump env/cwd/exe/sys.path for diffing shell vs orchestrator
    ancestry (the idalib shim learned this the hard way)."""
    dump = Path(tempfile.gettempdir()) / f"suspex_ghidra_shim_env_{os.getpid()}.txt"
    try:
        with open(dump, "w", encoding="utf-8") as fh:
            fh.write(f"pid={os.getpid()}\n")
            fh.write(f"executable={sys.executable}\n")
            fh.write(f"cwd={os.getcwd()}\n")
            fh.write(f"sys.prefix={sys.prefix}\n")
            fh.write(f"sys.base_prefix={sys.base_prefix}\n")
            fh.write("sys.path:\n")
            for p in sys.path:
                fh.write(f"  {p}\n")
            fh.write("env:\n")
            for k in sorted(os.environ):
                fh.write(f"  {k}={os.environ[k]}\n")
        _log(f"shim: env dump -> {dump}")
    except Exception as exc:  # noqa: BLE001
        _log(f"shim: env dump failed: {exc}")
