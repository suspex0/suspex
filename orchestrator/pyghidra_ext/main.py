"""Backend entrypoint: JVM + shared project + SSE server.

Spawned by ``ghidra_shim.backend._backend_cmd`` as::

    python suspex_pyghidra_ext.py --port N \
        --project-dir <artifacts>/ghidra_project [--project-name suspex]
        [--ghidra-dir D:\\Apps\\ghidra] [--java-home ...] [--heap-mb 8192]

GHIDRA_INSTALL_DIR / JAVA_HOME env vars also work (explicit CLI wins).
"""
from __future__ import annotations

import argparse
import sys

from .state import STATE, _log


def _install_stdin_watchdog() -> None:
    """Die with the parent shim.

    The shim spawns us with stdin=PIPE and holds the write end. If the
    shim is killed (TerminateProcess skips atexit, so the shim's own
    cleanup never runs) the OS closes that handle, the pipe breaks, and
    we exit — otherwise the orphaned JVM keeps the project lock forever
    and the next backend can never adopt it. Opt-in via
    SUSPX_GHIDRA_STDIN_WATCH=1 so standalone launches are unaffected.

    NB: a blocking ``sys.stdin.read()`` here wedged the JVM bootstrap
    (zero output, no progress) — poll with PeekNamedPipe instead.
    """
    import os
    import threading
    import time as _time
    if os.environ.get("SUSPX_GHIDRA_STDIN_WATCH") != "1":
        return
    if os.name != "nt":
        # POSIX: parent-death detection needs prctl/kevent — skip for
        # now (locks are still auto-cleared on the next open attempt).
        return
    try:
        parent_pid = int(os.environ.get("SUSPX_GHIDRA_PARENT_PID", "0"))
    except ValueError:
        parent_pid = 0
    if not parent_pid:
        return

    def _watch() -> None:
        # NB: stdin-PIPE EOF can't be trusted on Windows — uv-venv
        # redirector launchers re-inherit handles into grandchildren, so
        # the pipe write end outlives the real shim. Poll the parent's
        # PID instead: OpenProcess fails once the shim is dead (a stale
        # PID reused by an unrelated proc is an accepted edge case).
        import ctypes
        kernel32 = ctypes.windll.kernel32
        SYNCHRONIZE = 0x00100000
        while True:
            h = kernel32.OpenProcess(SYNCHRONIZE, False, parent_pid)
            if not h:
                _log(f"parent watchdog: shim pid {parent_pid} gone; "
                     "exiting")
                os._exit(0)
            kernel32.CloseHandle(h)
            _time.sleep(5)

    threading.Thread(target=_watch, daemon=True,
                     name="parent-watchdog").start()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="suspex_pyghidra_ext")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--project-name", default="suspex")
    ap.add_argument("--ghidra-dir", default="")
    ap.add_argument("--java-home", default="")
    ap.add_argument("--heap-mb", type=int, default=8192)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    _install_stdin_watchdog()

    STATE.start_jvm(ghidra_dir=args.ghidra_dir,
                    java_home=args.java_home,
                    heap_mb=args.heap_mb,
                    verbose=args.verbose)
    STATE.open_project(args.project_dir, args.project_name)

    from .server import serve
    serve(args.host, args.port)
    return 0
