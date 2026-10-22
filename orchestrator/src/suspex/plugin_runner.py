"""Subprocess entry for plugin execution: `python -m suspex.plugin_runner`.

Builds a real SuspexSDK (own gRPC clients) from a view descriptor on stdin,
imports the plugin's run.py, calls run(sdk, params), and prints a single
JSON envelope on stdout. Anything the plugin prints lands on stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import inspect
import json
import sys
import traceback
from pathlib import Path

from .agent_client import AgentClient
from .findings import FindingsLedger
from .plugins import PluginError, load_meta, validate_params
from .sdk import SymbolsApi, SuspexSDK


def _load_run_fn(plugin_dir: Path):
    spec = importlib.util.spec_from_file_location(f"suspex_plugin_{plugin_dir.name}",
                                                  plugin_dir / "run.py")
    if spec is None or spec.loader is None:
        raise PluginError(f"cannot import {plugin_dir / 'run.py'}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, "run", None)
    if fn is None:
        raise PluginError(f"{plugin_dir / 'run.py'} does not define run(sdk, params)")
    return fn


async def _main() -> int:
    ap = argparse.ArgumentParser(prog="suspex.plugin_runner")
    ap.add_argument("--plugin-dir", required=True)
    ap.add_argument("--params-json", default="",
                    help="params JSON; omitted -> read payload.params from stdin")
    args = ap.parse_args()

    raw = sys.stdin.read() if not sys.stdin.isatty() else "{}"
    payload = json.loads(raw or "{}")
    meta = load_meta(Path(args.plugin_dir))
    if meta is None:
        print(json.dumps({"ok": False, "error": f"no plugin.yaml in {args.plugin_dir}"}))
        return 1
    try:
        raw_params = args.params_json if args.params_json.strip() else json.dumps(
            payload.get("params") or {})
        params = validate_params(meta.params, json.loads(raw_params))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 1

    clients: dict[str, AgentClient] = {}
    try:
        for name, ep in (payload.get("views") or {}).items():
            client = AgentClient(ep["host"], ep["port"], ep.get("token", ""),
                                 ep.get("timeout_ms", 10000))
            await client.connect()
            clients[name] = client

        nt_build = int(payload.get("nt_build") or 0)
        if not nt_build and "kernel" in clients:
            try:
                nt_build = int((await clients["kernel"].status()).get("os_build") or 0)
            except Exception:
                pass

        ledger = FindingsLedger(payload["ledger"]) if payload.get("ledger") else None

        run_fn = _load_run_fn(Path(args.plugin_dir))
        sym = payload.get("symbols") or {}
        symbols_api = SymbolsApi(str(sym.get("cache_dir", "")),
                                 bool(sym.get("allow_download", True)),
                                 sym.get("servers"))
        sdk = SuspexSDK(clients=clients, ledger=ledger,
                        session_id=payload.get("session_id", ""),
                        nt_build=nt_build, symbols=symbols_api,
                        artifacts_dir=payload.get("artifacts_dir", ""))

        async def invoke():
            result = run_fn(sdk, params)
            if inspect.isawaitable(result):
                result = await result
            return result or {}

        with contextlib.redirect_stdout(sys.stderr):
            result = await invoke()
        print(json.dumps({"ok": True, "result": result}, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }))
        return 1
    finally:
        for c in clients.values():
            try:
                await c.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
