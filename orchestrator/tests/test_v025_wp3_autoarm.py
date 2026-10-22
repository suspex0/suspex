"""v0.25 WP3 — watchdog.auto_arm via snapshot.auto_arm_after_load.

Cases exercised:

- configured + driver loaded + watchdog_list empty -> _auto_kick_start
  arms the id and an orchestrator kicker starts pumping
- unconfigured / driver absent -> None, no arm attempted
- the id already armed driver-side -> skipped (idempotent, no re-arm)
- a live local kicker -> skipped on the repeat call
"""
from __future__ import annotations

import asyncio
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
from suspex.snapshot import auto_arm_after_load


class _WdgFake:
    """Client double — status/driver_state + watchdog RPCs."""

    def __init__(self, driver_state: str = "DRIVER_SERVICE") -> None:
        self._driver_state = driver_state
        self.entries: list[dict[str, Any]] = []
        self.arm_calls: list[dict[str, Any]] = []
        self.kick_calls = 0

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "driver_state": self._driver_state}

    async def watchdog_list(self) -> dict[str, Any]:
        return {"ok": True, "count": len(self.entries),
                "entries": list(self.entries)}

    async def watchdog_arm(self, wid: int, deadline_ms: int,
                           bugcheck_code: int = 0, flags: int = 0,
                           cookie: int = 0, label: str = "") -> dict[str, Any]:
        self.arm_calls.append({"id": wid, "deadline_ms": deadline_ms,
                               "flags": flags, "cookie": cookie,
                               "label": label})
        return {"ok": True, "id": wid}

    async def watchdog_kick(self, wid: int, deadline_ms: int = 0,
                            cookie: int = 0) -> dict[str, Any]:
        self.kick_calls += 1
        return {"ok": True, "id": wid}

    async def watchdog_disarm(self, wid: int) -> dict[str, Any]:
        return {"ok": True, "id": wid}


def _ctx(tmp_path, auto_arm: dict | None) -> Context:
    cfg = SuspexConfig()
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    cfg.watchdog.auto_arm = auto_arm or {}
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    return Context(
        cfg=cfg, session=session, ledger=ledger, bridge=bridge,
        clients=clients_reg,
        leases=LeaseManager(
            publish_event=lambda ev: asyncio.create_task(
                clients_reg.publish(ev))),
        ownership=OwnershipRegistry())


async def _stop_kickers(ctx: Context) -> None:
    for key, st in list(ctx._auto_kicks.items()):
        task = st.get("task")
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        ctx._auto_kicks.pop(key, None)


async def test_v025_wp3_autoarm_arms_when_configured(tmp_path) -> None:
    ctx = _ctx(tmp_path, {"id": 1, "deadline_ms": 45000,
                          "interval_ms": 10000, "label": "bringup"})
    client = _WdgFake()

    res = await auto_arm_after_load(ctx, client, "kernel")
    try:
        assert res is not None and res["ok"] is True, res
        assert res["id"] == 1
        assert client.arm_calls == [
            {"id": 1, "deadline_ms": 45000, "flags": 0,
             "cookie": 0, "label": "bringup"}]
        state = ctx._auto_kicks.get("kernel:1")
        assert state is not None and not state["task"].done()

        # Repeat call with the kicker live -> idempotent skip.
        res2 = await auto_arm_after_load(ctx, client, "kernel")
        assert res2 is None
        assert len(client.arm_calls) == 1
    finally:
        await _stop_kickers(ctx)


async def test_v025_wp3_autoarm_skips_when_already_armed(tmp_path) -> None:
    ctx = _ctx(tmp_path, {"id": 2, "deadline_ms": 45000,
                          "interval_ms": 10000, "label": "boot"})
    client = _WdgFake()
    # Driver-side list already carries the id (a previous lifetime, or a
    # peer that armed it manually) -> no re-arm.
    client.entries = [{"id": 2, "deadline_us": 60000000,
                       "kick_count": 5, "label": "boot"}]

    res = await auto_arm_after_load(ctx, client, "kernel")
    assert res is None
    assert client.arm_calls == []
    assert "kernel:2" not in ctx._auto_kicks


async def test_v025_wp3_autoarm_no_config_or_no_driver(tmp_path) -> None:
    ctx = _ctx(tmp_path, None)
    client = _WdgFake()
    assert await auto_arm_after_load(ctx, client, "kernel") is None
    assert client.arm_calls == []

    ctx2 = _ctx(tmp_path, {"id": 1, "deadline_ms": 45000,
                           "interval_ms": 10000})
    client2 = _WdgFake(driver_state="DRIVER_ABSENT")
    assert await auto_arm_after_load(ctx2, client2, "kernel") is None
    assert client2.arm_calls == []
