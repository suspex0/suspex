"""v0.17 E-1: watchdog state hygiene + ownership scoping.

Covers the pump/state edges that don't need a live driver:

  * E-1a: NOT_FOUND from the target must mark the kicker as stopped and
    let ``_auto_kick_status`` reap the entry (no zombie kickers).
  * E-1a: ``task_alive`` / ``stopped`` / ``stopped_reason`` fields exposed.
  * E-1b: ``watchdog_manage(action="list")`` annotates each row with
    owner + kicker state.
  * E-1c: ownership-scoped ``arm`` refuses a foreign id and warns on
    kickerless bare arms.
  * E-1d: ``disarm`` releases the ownership tag and clears kicker state.
"""

from __future__ import annotations

import asyncio
import json as _json
from types import SimpleNamespace
from typing import Any

import pytest

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp import tools as tools_mod
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


# ---------------------------------------------------------------------------
# _auto_kick_status reaper + pump-state fields (E-1a)
# ---------------------------------------------------------------------------


def _ctx_stub() -> SimpleNamespace:
    """Minimal namespace with the fields ``_auto_kick_status`` reads."""
    return SimpleNamespace(_auto_kicks={})


def _fake_state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "deadline_ms": 45000,
        "interval_ms": 10000,
        "started_ts": 0.0,
        "kicks": 0,
        "last_kick_ts": 0.0,
        "last_error": "",
        "last_result": {},
        "task": None,
    }
    base.update(overrides)
    return base


def test_e_1a_status_exposes_task_alive_stopped_fields():
    ctx = _ctx_stub()
    ctx._auto_kicks["kernel:1"] = _fake_state()
    out = tools_mod._auto_kick_status(ctx)
    assert out["ok"] is True
    row = out["auto_kickers"][0]
    assert row["task_alive"] is False
    assert row["stopped"] is False
    assert row["stopped_reason"] == ""


def test_e_1a_status_reaps_stale_stopped_kickers():
    ctx = _ctx_stub()
    ctx._auto_kicks["kernel:1"] = _fake_state(
        stopped=True, stopped_reason="watchdog_not_found",
        # 2 minutes ago — well past the 60 s grace window.
        stopped_ts=__import__("time").time() - 120,
    )
    out = tools_mod._auto_kick_status(ctx)
    # Reaped: the row is gone.
    assert out["count"] == 0
    assert "kernel:1" not in ctx._auto_kicks


def test_e_1a_status_keeps_recent_stopped_within_grace_window():
    ctx = _ctx_stub()
    ctx._auto_kicks["kernel:1"] = _fake_state(
        stopped=True, stopped_reason="watchdog_not_found",
        stopped_ts=__import__("time").time() - 5,
    )
    out = tools_mod._auto_kick_status(ctx)
    # Not reaped yet — still there with stopped=True.
    assert out["count"] == 1
    row = out["auto_kickers"][0]
    assert row["stopped"] is True
    assert row["stopped_reason"] == "watchdog_not_found"


class _FakeClient:
    """AgentClient just enough for _auto_kick_start's pump path."""

    def __init__(self, kick_results: list[dict[str, Any]]) -> None:
        # Each `watchdog_kick` returns the next entry; the last one repeats.
        self._results = kick_results

    async def watchdog_arm(self, wid, deadline_ms, *, bugcheck_code, flags,
                           cookie, label):
        return {"ok": True, "id": wid, "deadline_ms": deadline_ms}

    async def watchdog_kick(self, wid, *, deadline_ms, cookie):
        if not self._results:
            return {"ok": True, "id": wid}
        r = self._results.pop(0) if len(self._results) > 1 else self._results[0]
        return r

    async def watchdog_disarm(self, wid):
        return {"ok": True, "id": wid}

    async def watchdog_list(self):
        return []


def test_e_1a_not_found_marks_stopped_not_leaked():
    """The pump receives NOT_FOUND, exits, and the state is marked stopped
    (not popped) so a follow-up ``auto_status`` call can still see the
    reason. After the grace window it is reaped."""
    async def go():
        ctx = _ctx_stub()
        client = _FakeClient([
            {"ok": False, "error": "STATUS_NOT_FOUND: watchdog id not registered"},
        ])
        started = await tools_mod._auto_kick_start(
            ctx, client, "kernel", 1, deadline_ms=400, interval_ms=100,
            bugcheck_code=0, cookie=0, label="", replace=False,
        )
        assert started["ok"] is True
        # Give the pump a couple of ticks to see NOT_FOUND and exit.
        await asyncio.sleep(0.35)
        state = ctx._auto_kicks["kernel:1"]
        assert state["stopped"] is True
        assert state["stopped_reason"] == "watchdog_not_found"
        # The state row is still there (not popped) so status can render it.
        status = tools_mod._auto_kick_status(ctx)
        assert status["count"] == 1
        assert status["auto_kickers"][0]["stopped"] is True
        assert status["auto_kickers"][0]["task_alive"] is False
        # Simulate 120 s later — reaper should drop the entry.
        state["stopped_ts"] -= 120
        status2 = tools_mod._auto_kick_status(ctx)
        assert status2["count"] == 0

    asyncio.run(go())


# ---------------------------------------------------------------------------
# End-to-end watchdog_manage(action=...) tests via the FastMCP server so the
# guard funnel + envelope shape are covered too (E-1b, E-1c, E-1d).
# ---------------------------------------------------------------------------


class _FakeWdgClient:
    """AgentClient just enough for the watchdog_manage arm/disarm/list path.

    ``armed_ids`` is the current driver-side set of armed slots. Every action
    the tool calls goes through the fake client so tests can assert the tool
    body's ownership + refusal branches without a live target.
    """

    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = 9000
        self.token = ""
        self.endpoint = "127.0.0.1:9000"
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.armed_ids: dict[int, dict[str, Any]] = {}

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "driver_state": "DRIVER_SERVICE"}

    async def close(self) -> None:
        return None

    async def watchdog_arm(self, wid: int, deadline_ms: int, *,
                            bugcheck_code: int, flags: int, cookie: int,
                            label: str) -> dict[str, Any]:
        if wid in self.armed_ids and not (flags & 1):
            return {"ok": False,
                    "error": "STATUS_OBJECT_NAME_COLLISION: slot in use"}
        self.armed_ids[wid] = {"id": wid, "deadline_ms": deadline_ms,
                                "label": label, "cookie": cookie}
        return {"ok": True, "id": wid, "deadline_ms": deadline_ms}

    async def watchdog_disarm(self, wid: int) -> dict[str, Any]:
        self.armed_ids.pop(wid, None)
        return {"ok": True, "id": wid}

    async def watchdog_list(self) -> list[dict[str, Any]]:
        return [dict(v) for v in self.armed_ids.values()]

    def recent_ops(self, limit: int = 32) -> list[dict[str, Any]]:
        return []


async def _mk_ctx(tmp_path) -> tuple[Context, Any, _FakeWdgClient]:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=9000)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    fake = _FakeWdgClient()
    # Inject the fake directly so no real connect / TCP probe fires.
    session.clients["kernel"] = fake  # type: ignore[assignment]
    session.owners["kernel"] = "peer-E"
    session.refs["kernel"] = {"peer-E": 1}
    server = build_server(ctx)
    return ctx, server, fake


async def _call(server, tool: str, args: dict, *, peer: str = "peer-E") -> dict:
    token = CLIENT_ID.set(peer)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    return body if isinstance(body, dict) else {}


def _flatten(env: dict) -> dict:
    """Merge data + error into a flat dict so tests can assert both success
    and failure envelopes with the same key lookups."""
    out: dict[str, Any] = {"ok": env.get("ok")}
    if isinstance(env.get("data"), dict):
        out.update(env["data"])
    if isinstance(env.get("error"), dict):
        for k, v in env["error"].items():
            out.setdefault(k, v)
    err_kind = env.get("error", {}).get("kind") if isinstance(env.get("error"), dict) else None
    out["kind"] = err_kind or env.get("kind")
    out["warnings"] = env.get("warnings") or []
    return out


# ---------------------------------------------------------------------------
# E-1b — list annotates owner + kicker
# ---------------------------------------------------------------------------


def test_e_1b_list_annotates_owner_and_kicker(tmp_path):
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        # Peer-E claims id=7 via arm; id=8 is claimed by "peer-X" outside our
        # session (ownership tag pre-populated) and armed on the driver.
        await ctx.ownership.claim("watchdog:kernel", "8", "peer-X")
        fake.armed_ids[7] = {"id": 7, "deadline_ms": 1000}
        fake.armed_ids[8] = {"id": 8, "deadline_ms": 1000}
        await ctx.ownership.claim("watchdog:kernel", "7", "peer-E")
        # Attach a kicker task marker for id=7 so list sees "attached".
        async def _noop():
            return None
        task = asyncio.create_task(asyncio.sleep(3600))
        ctx._auto_kicks["kernel:7"] = {
            "id": 7, "task": task, "interval_ms": 500,
            "started_ts": 0.0, "kicks": 0, "last_kick_ts": 0.0,
            "deadline_ms": 1000, "last_error": "", "last_result": {},
        }
        try:
            env = await _call(server, "watchdog_manage",
                              {"action": "list", "name": "kernel"})
            data = env.get("data") or {}
            rows = {r["id"]: r for r in data.get("watchdogs", [])}
            assert rows[7]["owner"] == "peer-E"
            assert rows[7]["foreign"] is False
            assert rows[7]["kicker"] == "attached"
            assert rows[7]["kicker_interval_ms"] == 500
            assert rows[8]["owner"] == "peer-X"
            assert rows[8]["foreign"] is True
            assert rows[8]["kicker"] == "none"
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(go())


# ---------------------------------------------------------------------------
# E-1c — foreign_owned + watchdog_collision refusals + bare-arm warning
# ---------------------------------------------------------------------------


def test_e_1c_foreign_arm_refused(tmp_path):
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        # A different peer owns id=5.
        await ctx.ownership.claim("watchdog:kernel", "5", "peer-X")
        env = await _call(server, "watchdog_manage",
                          {"action": "arm", "id": 5, "name": "kernel",
                           # v1.0.1 Phase 1.4: pass unsafe_without_kicker
                           # so the refusal path we're testing is foreign-
                           # owned, not the new no-kicker refusal.
                           "unsafe_without_kicker": True})
        flat = _flatten(env)
        assert flat["ok"] is False
        assert flat["kind"] == "foreign_owned"
        assert "peer-X" in (flat.get("owner") or "")

    asyncio.run(go())


def test_e_1c_replace_true_bypasses_foreign_owned(tmp_path):
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        await ctx.ownership.claim("watchdog:kernel", "5", "peer-X")
        env = await _call(server, "watchdog_manage",
                          {"action": "arm", "id": 5, "name": "kernel",
                           "replace": True,
                           # v1.0.1 Phase 1.4: unprotected arm needs the
                           # explicit opt-in (no kicker in this test).
                           "unsafe_without_kicker": True})
        # Success — replace=True is the "yes I'm stealing" acknowledgement.
        assert env.get("ok") is True

    asyncio.run(go())


def test_e_1c_bare_rearm_warns_watchdog_collision(tmp_path):
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        # Pretend id=3 is already armed on the driver without an ownership tag.
        fake.armed_ids[3] = {"id": 3, "deadline_ms": 1000}
        env = await _call(server, "watchdog_manage",
                          {"action": "arm", "id": 3, "name": "kernel",
                           "unsafe_without_kicker": True})
        flat = _flatten(env)
        assert flat["ok"] is False
        assert flat["kind"] == "watchdog_collision"
        assert "auto_kick" in (flat.get("hint") or "")

    asyncio.run(go())


def test_e_1c_bare_arm_refuses_without_kicker(tmp_path):
    """v1.0.1 Phase 1.4: bare arm without a kicker is REFUSED by default
    (breaking from v0.17's warn-only path). Pass unsafe_without_kicker to
    opt into the fire-and-forget behavior."""
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        env = await _call(server, "watchdog_manage",
                          {"action": "arm", "id": 2, "name": "kernel",
                           "deadline_ms": 30000})
        flat = _flatten(env)
        assert flat["ok"] is False
        assert flat["kind"] == "watchdog_no_kicker"
        assert "unsafe_without_kicker" in (flat.get("hint") or "")
        # Opting in via unsafe_without_kicker makes the same call succeed.
        env2 = await _call(server, "watchdog_manage",
                           {"action": "arm", "id": 2, "name": "kernel",
                            "deadline_ms": 30000,
                            "unsafe_without_kicker": True})
        assert env2.get("ok") is True

    asyncio.run(go())


def test_e_1c_arm_claims_ownership(tmp_path):
    """After a successful arm the tag records the current caller so a
    follow-up foreign arm hits foreign_owned refusal."""
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        env1 = await _call(server, "watchdog_manage",
                           {"action": "arm", "id": 9, "name": "kernel",
                            "unsafe_without_kicker": True},
                           peer="peer-E")
        assert env1.get("ok") is True
        owner = await ctx.ownership.owner_of("watchdog:kernel", "9")
        assert owner == "peer-E"
        env2 = await _call(server, "watchdog_manage",
                           {"action": "arm", "id": 9, "name": "kernel",
                            "unsafe_without_kicker": True},
                           peer="peer-Q")
        flat = _flatten(env2)
        assert flat["ok"] is False
        assert flat["kind"] == "foreign_owned"

    asyncio.run(go())


# ---------------------------------------------------------------------------
# E-1d — disarm releases ownership
# ---------------------------------------------------------------------------


def test_e_1d_disarm_releases_ownership(tmp_path):
    async def go():
        ctx, server, fake = await _mk_ctx(tmp_path)
        # Arm first so ownership is claimed by peer-E.
        arm = await _call(server, "watchdog_manage",
                          {"action": "arm", "id": 4, "name": "kernel",
                           "unsafe_without_kicker": True},
                          peer="peer-E")
        assert arm.get("ok") is True
        assert await ctx.ownership.owner_of("watchdog:kernel", "4") == "peer-E"
        # Same peer disarms — tag drops.
        dis = await _call(server, "watchdog_manage",
                          {"action": "disarm", "id": 4, "name": "kernel"},
                          peer="peer-E")
        assert dis.get("ok") is True
        assert await ctx.ownership.owner_of("watchdog:kernel", "4") is None
        # And a different peer can now arm the same id without refusal.
        env2 = await _call(server, "watchdog_manage",
                           {"action": "arm", "id": 4, "name": "kernel",
                            "unsafe_without_kicker": True},
                           peer="peer-Q")
        assert env2.get("ok") is True

    asyncio.run(go())
