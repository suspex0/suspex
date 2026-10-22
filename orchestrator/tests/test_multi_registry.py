"""clients.py — ClientRegistry register/list/reap semantics.

Split out of test_multi_agent.py.
"""

from __future__ import annotations

from suspex.clients import ClientRegistry


async def test_client_registry_register_and_list() -> None:
    reg = ClientRegistry()
    await reg.register("peer-A")
    await reg.register("peer-B")
    await reg.touch("peer-A")
    peers = await reg.list_peers()
    assert {p["client_id"] for p in peers} == {"peer-A", "peer-B"}


async def test_client_registry_held_attach_and_refs() -> None:
    reg = ClientRegistry()
    await reg.register("peer-A")
    await reg.held_attach_add("peer-A", "kernel", 4321)
    await reg.refcount_add("peer-A", "kernel")
    await reg.refcount_add("peer-A", "kernel")
    peers = await reg.list_peers()
    peer = next(p for p in peers if p["client_id"] == "peer-A")
    assert 4321 in peer["held_attach_pids"]
    assert "kernel" in peer["connected_views"]
    # decrement once — still positive
    await reg.refcount_remove("peer-A", "kernel")
    peer = (await reg.list_peers())[0]
    assert "kernel" in peer["connected_views"]
    # decrement to zero — view drops out
    await reg.refcount_remove("peer-A", "kernel")
    peer = (await reg.list_peers())[0]
    assert peer["connected_views"] == []


async def test_client_registry_reap_idle_skips_active_holders() -> None:
    reg = ClientRegistry()
    await reg.register("peer-A")
    await reg.held_attach_add("peer-A", "kernel", 99)
    await reg.register("peer-B")
    # Force both to look old
    async with reg._lock:  # accessing internals for the test only
        for info in reg._clients.values():
            info.last_op = 0.0
    reaped = await reg.reap_idle(idle_reap_s=1.0)
    assert reaped == ["peer-B"]  # peer-A had held_attach, retained
