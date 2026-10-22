"""v0.25 WP1 — boot-change notification surface.

`wait_boot_change` (success + timeout), the session boot monitor's
pending-notice drain through `status`, and `crash_state`'s auto-attached
minidump on `rebooted=True`.
"""
from __future__ import annotations

import asyncio
import hashlib
import json as _json
import struct
from pathlib import Path
from typing import Any

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


def _kernel_dump_bytes() -> bytes:
    hdr = bytearray(0x2000)
    hdr[0x00:0x04] = b"PAGE"
    hdr[0x04:0x08] = b"DU64"
    struct.pack_into("<I", hdr, 0x08, 15)
    struct.pack_into("<I", hdr, 0x38, 0xE2)          # MANUALLY_INITIATED
    struct.pack_into("<4Q", hdr, 0x40, 7, 45000, 40000, 0xC0FFEE)
    struct.pack_into("<Q", hdr, 0x10, 0x1AA000)
    struct.pack_into("<I", hdr, 0xF98, 4)            # TRIAGE
    tri = bytearray(0x80)
    return bytes(hdr) + bytes(tri)


DUMP_BYTES = _kernel_dump_bytes()
DUMP_DIR = r"C:\Windows\Minidump"
DUMP_REMOTE = DUMP_DIR + r"\Mini101826-01.dmp"


class _SeqClient:
    """Status answers from a scripted boot-identity sequence."""

    def __init__(self, statuses: list[dict]) -> None:
        self._statuses = list(statuses)
        self._idx = 0
        self.status_calls = 0
        self.last_op_ts = 1.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    async def status(self) -> dict[str, Any]:
        self.status_calls += 1
        row = self._statuses[min(self._idx, len(self._statuses) - 1)]
        if self._idx < len(self._statuses) - 1:
            self._idx += 1
        return dict(row)

    async def host_info(self, **_kw) -> dict:
        return {"ok": False, "error": "no host_info on the fake"}

    async def recent_ops_agent(self, limit: int = 32,
                               include_prior: bool = True) -> dict:
        # agent_start_epoch_ms > last_op_ts -> crash_state marks rebooted.
        return {"ok": True, "agent_start_epoch_ms": 1_800_000_000_000,
                "ops": []}

    async def file_tail(self, path: str, bytes_wanted: int = 0,
                        line_align: bool = True) -> dict:
        return {"ok": True, "tail": "[driver] last line before bugcheck"}

    def recent_ops(self, n: int) -> list[dict]:
        return [{"op": "mem_read", "ts": 1.0}]

    async def file_list_dir(self, path: str,
                            recursive: bool = False) -> list[dict]:
        return [{"name": "Mini101826-01.dmp", "dir": False,
                 "mtime_unix": 200, "size": len(DUMP_BYTES)}]

    async def file_download(self, remote: str, local: str,
                            offset: int = 0, length: int = 0) -> dict:
        assert remote == DUMP_REMOTE
        chunk = DUMP_BYTES[offset:offset + length] if length \
            else DUMP_BYTES[offset:]
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(chunk)
        return {"ok": True, "bytes": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest()}

    async def mem_modules(self, pid: int, kernel: bool) -> list[dict]:
        return [{"name": "ntoskrnl.exe", "base": 0xFFFFF80000000000,
                 "size": 0x1000000}]


def _status(boot: int, inst: str = "inst-1") -> dict:
    return {"ok": True, "boot_epoch_ms": boot, "agent_instance_id": inst,
            "driver_state": "DRIVER_SERVICE"}


async def _build_ctx(tmp_path, monkeypatch):
    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None
    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-wp1")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


# ----------------------------------------------------------------------- #
# wait_boot_change
# ----------------------------------------------------------------------- #

async def test_wait_boot_change_returns_on_third_poll(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    # attempt 1 records the baseline, attempt 2 same, attempt 3 rebooted.
    ctx.session.clients["kernel"] = _SeqClient(
        [_status(1111), _status(1111), _status(2222)])
    body = await _call(server, "target_manage",
                       {"action": "wait_boot_change", "timeout_s": 10.0})
    assert body["ok"] is True, body
    assert body["attempts"] == 3
    assert body["boot_change"]["kind"] == "new_boot"
    assert body["boot_change"]["prev_boot_epoch_ms"] == 1111
    assert body["boot_change"]["boot_epoch_ms"] == 2222
    assert body["elapsed_s"] >= 0


async def test_wait_boot_change_timeout(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _SeqClient([_status(1111)])
    body = await _call(server, "target_manage",
                       {"action": "wait_boot_change", "timeout_s": 1.2})
    assert body["ok"] is False, body
    assert body["kind"] == "wait_timeout"
    assert body["last_status_kind"] == "ok"
    assert body["attempts"] >= 1
    assert body["boot_identity"]["boot_epoch_ms"] == 1111


async def test_wait_boot_change_drains_pending_notice(tmp_path, monkeypatch):
    """A notice the monitor already parked satisfies the wait on the
    first poll — the monitor won the race, wait just reports it."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _SeqClient([_status(2222)])
    # Monitor already recorded the new identity (2222) and parked the
    # notice — the lazy detector sees no further change, so the wait
    # reports exactly what the monitor found.
    ctx.session._boot_ids["kernel"] = {
        "boot_epoch_ms": 2222, "agent_instance_id": "inst-1"}
    ctx.session.pending_boot_notices["kernel"] = {
        "kind": "new_boot", "view": "kernel",
        "prev_boot_epoch_ms": 1111, "boot_epoch_ms": 2222,
        "agent_instance_id": "inst-1", "source": "boot_monitor"}
    body = await _call(server, "target_manage",
                       {"action": "wait_boot_change", "timeout_s": 5.0})
    assert body["ok"] is True, body
    assert body["attempts"] == 1
    assert body["boot_change"]["source"] == "boot_monitor"


# ----------------------------------------------------------------------- #
# boot monitor -> pending_boot_notices -> status drain
# ----------------------------------------------------------------------- #

async def test_boot_monitor_parks_notice_and_status_drains(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _SeqClient(
        [_status(1111), _status(2222), _status(2222), _status(2222),
         _status(2222)])
    assert ctx.session.start_boot_monitor("kernel", 0.02) is True
    # starting again is a no-op while the first is alive
    assert ctx.session.start_boot_monitor("kernel", 0.02) is False
    try:
        for _ in range(300):
            if "kernel" in ctx.session.pending_boot_notices:
                break
            await asyncio.sleep(0.01)
        assert "kernel" in ctx.session.pending_boot_notices, (
            "monitor never parked the new_boot notice")
        assert ctx.session.pending_boot_notices["kernel"]["kind"] == \
            "new_boot"
    finally:
        ctx.session.stop_boot_monitor("kernel")
    assert ctx.session.boot_monitor_running("kernel") is False
    body = await _call(server, "target_manage", {"action": "status"})
    assert body["ok"] is True, body
    bc = body.get("boot_change")
    assert bc is not None, body
    assert bc["kind"] == "new_boot"
    assert bc["prev_boot_epoch_ms"] == 1111
    assert bc["boot_epoch_ms"] == 2222
    # drained — the next status doesn't repeat the notice.
    assert ctx.session.pending_boot_notices == {}


async def test_monitor_interval_zero_disables(tmp_path, monkeypatch):
    """interval_s <= 0 is the documented disable: no task spawned."""
    ctx, _server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _SeqClient([_status(1111)])
    assert ctx.session.start_boot_monitor("kernel", 0.0) is False
    assert ctx.session.boot_monitor_running("kernel") is False


# ----------------------------------------------------------------------- #
# crash_state -> minidump attach
# ----------------------------------------------------------------------- #

async def test_crash_state_attaches_minidump_on_reboot(
        tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _SeqClient([_status(2222)])
    body = await _call(server, "target_manage", {"action": "crash_state"})
    assert body["ok"] is True, body
    assert body["rebooted"] is True
    md = body.get("minidump")
    assert md is not None, body
    assert md["ok"] is True
    assert md["bugcheck"]["code"] == 0xE2
    assert md["bugcheck"]["name"] == "MANUALLY_INITIATED_CRASH"
    assert md["watchdog"]["id"] == 7
    assert md["watchdog"]["cookie"] == 0xC0FFEE
    assert md["fired_by"] == "suspex_watchdog"
    assert md["source"]["remote_path"] == DUMP_REMOTE


async def test_crash_state_minidump_never_breaks_breadcrumb(
        tmp_path, monkeypatch):
    """Dump pull failing must attach minidump_error while the breadcrumb
    still answers — the one-call post-mortem stays honest."""

    class _NoDump(_SeqClient):
        async def file_list_dir(self, path, recursive=False):
            raise RuntimeError("minidump dir access denied")

    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    ctx.session.clients["kernel"] = _NoDump([_status(2222)])
    body = await _call(server, "target_manage",
                       {"action": "crash_state", "include_dump": True})
    assert body["ok"] is True, body
    assert body["breadcrumb"]["ok"] is True
    assert "minidump" not in body
    assert "access denied" in body.get("minidump_error", "")
