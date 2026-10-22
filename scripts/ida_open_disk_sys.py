"""Round-trip: pull C:\\Windows\\System32\\drivers\\disk.sys from the VM,
open it with idalib, then also stand up the ida-pro-mcp HTTP-SSE server on
the same binary and hit its /sse endpoint to confirm the MCP layer is live.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

# idapro can TerminateProcess on some analysis errors; force stdout to flush
# every line so we don't lose diagnostic prints across the failure.
sys.stdout.reconfigure(line_buffering=True)

from suspex.agent_client import AgentClient  # noqa: E402
from suspex.config import load_config  # noqa: E402


async def pull_from_vm(cfg_path: str, remote: str) -> Path:
    repo = Path(__file__).resolve().parents[1]
    cfg = load_config(repo / cfg_path)
    tgt = cfg.target_for()
    print(f"==> pulling {remote} from {tgt.host}:{tgt.port}")
    out = repo / "artifacts" / "_incoming" / Path(remote).name
    out.parent.mkdir(parents=True, exist_ok=True)
    c = AgentClient(tgt.host, tgt.port, tgt.token)
    await asyncio.wait_for(c.connect(), timeout=10)
    try:
        r = await c.file_download(remote, str(out))
    finally:
        await c.close()
    print(f"    downloaded {r['bytes']} bytes  sha256={r['sha256'][:16]}...")
    return out


def idapro_direct(path: Path) -> None:
    print("\n==> idapro direct analysis")
    import idapro
    print("    enabling console messages...")
    try:
        idapro.enable_console_messages(True)
    except Exception as exc:
        print(f"    (enable_console_messages: {exc})")
    print(f"    opening database: {path}")
    rc = idapro.open_database(str(path), run_auto_analysis=True)
    print(f"    open_database rc={rc}")
    if rc:
        raise RuntimeError(f"idapro.open_database failed rc={rc}")
    try:
        import ida_auto, ida_funcs, ida_name, idc  # noqa: F401
        ida_auto.auto_wait()
        n = ida_funcs.get_func_qty()
        print(f"    functions: {n}")
        for i in range(min(n, 8)):
            f = ida_funcs.getn_func(i)
            if not f:
                continue
            nm = ida_name.get_ea_name(f.start_ea) or "?"
            print(f"      {i:2d}: {f.start_ea:#010x}  {nm}")
        entry = idc.get_func_attr(idc.get_name_ea(0, "DriverEntry"), 0)
        if entry != idc.BADADDR:
            print(f"    DriverEntry @ {entry:#x}")
    finally:
        idapro.close_database(save=False)
    print("    idapro direct OK")


def pick_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_sse(port: int, timeout_s: float = 300) -> bool:
    url = f"http://127.0.0.1:{port}/sse"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                # SSE endpoint keeps the connection open; a successful
                # HTTP 200 is enough to prove it's serving
                if 200 <= r.status < 300:
                    return True
        except urllib.error.HTTPError as e:
            if e.code in (200, 204, 405):  # 405 = method-not-allowed but bound
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def idalib_mcp_subprocess(path: Path) -> None:
    print("\n==> idalib-mcp HTTP-SSE server")
    venv = Path(sys.executable).parent
    exe = venv / "idalib-mcp.exe"
    if not exe.exists():
        print(f"    idalib-mcp.exe not found at {exe}")
        return
    port = pick_free_port()
    print(f"    spawning: {exe.name} --host 127.0.0.1 --port {port} {path.name}")
    log_path = path.with_suffix(".idalib-mcp.log")
    log = open(log_path, "wb")
    proc = subprocess.Popen(
        [str(exe), "--host", "127.0.0.1", "--port", str(port), str(path)],
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        ok = wait_for_sse(port, timeout_s=300)
        print(f"    /sse reachable: {ok}")
        if not ok:
            print(f"    (log tail: {log_path})")
            log.flush()
            try:
                tail = log_path.read_bytes()[-1200:].decode("utf-8", "replace")
                print(tail)
            except Exception:
                pass
            return
        print(f"    MCP server is live on http://127.0.0.1:{port}/sse")
        print( "    (stop it any time; suspex0's future MCP client would connect here)")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
    print("    idalib-mcp round-trip OK")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--remote", default=r"C:\Windows\System32\drivers\disk.sys")
    args = ap.parse_args()

    path = await pull_from_vm(args.config, args.remote)

    # (a) idapro direct
    idapro_direct(path)

    # (b) same file, opened through the ida-pro-mcp SSE server. idalib holds a
    # process-wide lock on the analyzed image, so this must run AFTER the
    # direct path has closed the database.
    idalib_mcp_subprocess(path)

    print("\nOK: disk.sys pulled from VM, analyzed via idalib, then served by "
          "ida-pro-mcp on 127.0.0.1.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
