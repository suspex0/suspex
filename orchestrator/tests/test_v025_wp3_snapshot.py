"""v0.25 WP3 — SnapshotPump periodic pre-crash capture.

Cases exercised:

- a tick writes <name>.bin + an index.jsonl row carrying
  ts/name/va/size/sha256/ok under artifacts/snapshots/<boot_epoch_ms>/
- module+offset range spec resolves via mem_modules once per boot
- an injected mem_read failure lands {ok:false, error} and the pump
  keeps going — later ranges and later ticks still capture
- a boot-epoch change re-resolves cached addresses into a new dir
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest

from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context
from suspex.ownership import OwnershipRegistry
from suspex.session import Session
from suspex.snapshot import SnapshotPump


class _SnapFake:
    """Minimal client double — mem_read serves seed bytes or raises."""

    def __init__(self) -> None:
        self.seed = bytes(range(64))
        self.fail_addrs: set[int] = set()
        self.read_calls: list[tuple] = []
        self.modules_calls = 0

    async def mem_read(self, pid: int, addr: int, size: int,
                       space: str = "user", **kw: Any):
        self.read_calls.append((pid, addr, size, space))
        if addr in self.fail_addrs:
            raise RuntimeError("simulated read fault")
        return self.seed[:size]

    async def mem_modules(self, pid: int, kernel: bool = False,
                          **kw: Any) -> list[dict]:
        self.modules_calls += 1
        return [{"name": "ntoskrnl.exe", "base": 0xFFFFF80000000000,
                 "size": 0x1000000}]


def _ctx(tmp_path) -> Context:
    cfg = SuspexConfig()
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(
        cfg=cfg, session=session, ledger=ledger, bridge=bridge,
        clients=clients_reg,
        leases=LeaseManager(
            publish_event=lambda ev: asyncio.create_task(
                clients_reg.publish(ev))),
        ownership=OwnershipRegistry())
    # Wire the fake view + boot identity the way connect() would.
    fake = _SnapFake()
    session.clients["kernel"] = fake
    session._boot_ids["kernel"] = {"boot_epoch_ms": 4242}
    ctx._snap_fake = fake  # test handle
    return ctx


def _index_rows(path) -> list[dict]:
    p = path / "index.jsonl"
    return [json.loads(line) for line in
            p.read_text(encoding="utf-8").splitlines() if line.strip()]


async def test_v025_wp3_snapshot_tick_writes_bin_and_index(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    ranges = [{"name": "hv_log", "space": "kernel",
               "address": "0xfffff80000001000", "size": 32}]
    pump = SnapshotPump(ctx, "kernel", ranges, 30)
    await pump._tick()

    out = tmp_path / "artifacts" / "snapshots" / "4242"
    blob = (out / "hv_log.bin").read_bytes()
    assert blob == ctx._snap_fake.seed[:32]

    rows = _index_rows(out)
    assert len(rows) == 1
    row = rows[0]
    assert row["ok"] is True
    assert row["name"] == "hv_log"
    assert row["va"] == hex(0xFFFFF80000001000)
    assert row["size"] == 32
    assert row["sha256"] == hashlib.sha256(blob).hexdigest()
    assert row["ts"] > 0


async def test_v025_wp3_snapshot_failure_honest_gap(tmp_path) -> None:
    """A wedged range writes ok:false and doesn't kill the tick."""
    ctx = _ctx(tmp_path)
    fake = ctx._snap_fake
    ranges = [
        {"name": "dead", "space": "kernel",
         "address": "0xfffff80000002000", "size": 16},
        {"name": "alive", "space": "kernel",
         "address": "0xfffff80000003000", "size": 16},
    ]
    pump = SnapshotPump(ctx, "kernel", ranges, 30)
    fake.fail_addrs.add(0xFFFFF80000002000)
    await pump._tick()
    await pump._tick()  # a second tick still runs after the failure

    out = tmp_path / "artifacts" / "snapshots" / "4242"
    rows = _index_rows(out)
    assert len(rows) == 4  # 2 ranges x 2 ticks
    dead = [r for r in rows if r["name"] == "dead"]
    alive = [r for r in rows if r["name"] == "alive"]
    assert all(r["ok"] is False and "error" in r for r in dead)
    assert all(r["ok"] is True for r in alive)
    assert (out / "alive.bin").exists()
    assert not (out / "dead.bin").exists()


async def test_v025_wp3_snapshot_module_offset_resolves_once_per_boot(
        tmp_path) -> None:
    """module+offset resolves via mem_modules and caches per boot."""
    ctx = _ctx(tmp_path)
    fake = ctx._snap_fake
    ranges = [{"name": "kern", "space": "kernel",
               "address": "ntoskrnl.exe+0x10", "size": 8}]
    pump = SnapshotPump(ctx, "kernel", ranges, 30)
    await pump._tick()
    await pump._tick()
    assert fake.modules_calls == 1  # cached across ticks in one boot
    assert fake.read_calls[-1][1] == 0xFFFFF80000000000 + 0x10

    # New boot -> new dir + re-resolution against the new module map.
    ctx.session._boot_ids["kernel"] = {"boot_epoch_ms": 9999}
    await pump._tick()
    assert fake.modules_calls == 2
    assert (tmp_path / "artifacts" / "snapshots" / "9999" /
            "kern.bin").exists()
