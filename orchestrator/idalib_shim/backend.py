"""Backend-process helpers: how the shim spawns and inventories the
``suspex_idalib_ext`` child that fronts ida-pro-mcp.

Mechanical split-out from ``idalib_stdio_shim.py``; no behavior changes.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from .logging import _log


# Startup readiness knobs — how long the shim will wait for the backend
# TCP port to open and how often it polls.
READY_TIMEOUT_S = 230
POLL_INTERVAL_S = 0.7


def _backend_exe() -> Path:
    exe = Path(sys.executable).parent / "idalib-mcp.exe"
    if not exe.exists():
        raise RuntimeError(f"idalib-mcp.exe not found next to shim python: {exe}")
    return exe


def _backend_cmd(resolved: str, port: int) -> list[str]:
    """Direct spawn of our idalib extension entry.

    Bypasses the idalib-mcp.exe -> venv-redirector -> python launcher chain
    (that combo silently stalls when spawned by the orchestrator; works
    from a plain shell). Single python layer.

    Runs `suspex_idalib_ext.main()` — thin wrapper over ida-pro-mcp's
    `idalib_server` that additionally registers `create_function` and
    `exec_idapython`, plus honors the `SUSPX_IDA_NO_AUTO=1` env gate to
    skip auto-analysis (the vanilla server hardcodes `True`).
    """
    # ``suspex_idalib_ext.py`` lives next to the top-level facade
    # ``idalib_stdio_shim.py`` in ``orchestrator/``.  This module lives one
    # level deeper (``orchestrator/idalib_shim/backend.py``), so we walk
    # up one parent to reach the extension entry.
    ext = Path(__file__).resolve().parent.parent / "suspex_idalib_ext.py"
    return [sys.executable, str(ext), resolved, "--port", str(port)]


def _prevalidate_pe(path: str) -> None:
    """Refuse PEs the idalib loader is known to crash on.

    Specifically: two sections with the same name (nvlddmkm.sys ships two
    `.text` sections). idalib crashes with a NULL-read access violation
    in the PE loader on those, and the failure is silent — the shim just
    sees rc=1 with no useful log. Detect this here so the caller gets a
    real error instead of a mysterious crash.
    """
    try:
        with open(path, "rb") as fh:
            dos = fh.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return  # not a PE; nothing to check (dumps, raw blobs, …)
            e_lfanew = int.from_bytes(dos[0x3C:0x40], "little")
            fh.seek(e_lfanew)
            nt = fh.read(0x18)
            if len(nt) < 0x18 or nt[:4] != b"PE\0\0":
                return
            num_sections = int.from_bytes(nt[6:8], "little")
            size_opt = int.from_bytes(nt[0x14:0x16], "little")
            fh.seek(e_lfanew + 0x18 + size_opt)
            names: dict[bytes, int] = {}
            for _ in range(min(num_sections, 96)):
                hdr = fh.read(40)
                if len(hdr) < 40:
                    break
                nm = hdr[:8].rstrip(b"\x00")
                names[nm] = names.get(nm, 0) + 1
            dups = [nm.decode("ascii", "replace") for nm, c in names.items() if c > 1]
            if dups:
                raise RuntimeError(
                    f"idb_open: PE has duplicate section names ({dups!r}) — "
                    "idalib's PE loader crashes on this (silent access "
                    "violation, no useful log). Workaround: patch a copy "
                    "of the PE to rename the duplicates (e.g. `.text2`) "
                    "and reopen from the patched path.")
    except OSError as exc:
        _log(f"shim: PE prevalidate skipped for {path}: {exc}")


def _backend_names() -> list[str]:
    """Tool names the backend registers, via its rpc registry.

    Runs in a throwaway subprocess: importing idapro/ida modules pollutes
    this process's sys.modules (IDA init swaps shadowed modules), which
    breaks mcp's lazy type resolution in-process.
    """
    snippet = (
        "import json, importlib, idapro\n"
        "idapro.enable_console_messages(False)\n"
        "plugin = importlib.import_module('ida_pro_mcp.mcp-plugin')\n"
        "unsafe = set(getattr(plugin.rpc_registry, 'unsafe', []) or [])\n"
        "names = sorted(set(plugin.rpc_registry.methods) - unsafe)\n"
        "print('RESULT:' + json.dumps(names))\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True,
            text=True, encoding="utf-8", timeout=120, check=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT:"):
                return json.loads(line[len("RESULT:"):])
        raise ValueError("no RESULT: line in subprocess output")
    except Exception as exc:  # noqa: BLE001 - inventory is best-effort
        _log(f"shim: backend tool inventory unavailable: {exc}")
        return []


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _dump_startup_env() -> None:
    """Dump env/cwd/exe/sys.path for diffing shell vs orchestrator ancestry.

    The orchestrator-spawned shim silently stalled its backend chain even
    though the same command works from a plain shell; this file lets us
    diff the environments after a stall.
    """
    dump = Path(tempfile.gettempdir()) / f"suspex_idalib_shim_env_{os.getpid()}.txt"
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
