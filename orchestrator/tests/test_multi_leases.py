"""leases.py — LeaseManager acquire/release/wait/timeout/context-manager.

Split out of test_multi_agent.py.
"""

from __future__ import annotations

from suspex.leases import BusyInfo, LeaseHandle, LeaseManager


async def test_lease_acquire_release_publishes() -> None:
    events: list[dict] = []
    mgr = LeaseManager(publish_event=lambda ev: events.append(ev))
    handle = await mgr.acquire("debug:kernel:pid=100", "peer-A", wait_s=1.0)
    assert isinstance(handle, LeaseHandle)
    assert handle.owner == "peer-A"
    assert mgr.who_holds("debug:kernel:pid=100") == "peer-A"
    await mgr.release(handle)
    assert mgr.who_holds("debug:kernel:pid=100") is None
    kinds = [e["type"] for e in events]
    assert "lease_acquire" in kinds
    assert "lease_release" in kinds


async def test_lease_busy_nonblocking() -> None:
    mgr = LeaseManager(publish_event=lambda ev: None)
    h1 = await mgr.acquire("driver", "peer-A", wait_s=0)
    assert isinstance(h1, LeaseHandle)
    busy = await mgr.acquire("driver", "peer-B", wait_s=0)
    assert isinstance(busy, BusyInfo)
    assert busy.held_by == "peer-A"
    assert busy.waited_s == 0.0


async def test_lease_wait_up_to_timeout() -> None:
    mgr = LeaseManager(publish_event=lambda ev: None)
    h1 = await mgr.acquire("driver", "peer-A", wait_s=0)
    # Peer-B waits 0.1s then times out
    busy = await mgr.acquire("driver", "peer-B", wait_s=0.1)
    assert isinstance(busy, BusyInfo)
    assert busy.waited_s > 0.05


async def test_lease_release_by_owner() -> None:
    mgr = LeaseManager(publish_event=lambda ev: None)
    await mgr.acquire("debug:kernel:pid=1", "peer-A", wait_s=0)
    await mgr.acquire("debug:kernel:pid=2", "peer-A", wait_s=0)
    await mgr.acquire("debug:kernel:pid=3", "peer-B", wait_s=0)
    released = await mgr.release_by_owner("peer-A")
    assert set(released) == {"debug:kernel:pid=1", "debug:kernel:pid=2"}
    assert mgr.who_holds("debug:kernel:pid=3") == "peer-B"


async def test_lease_handle_as_async_context_manager() -> None:
    mgr = LeaseManager(publish_event=lambda ev: None)
    h = await mgr.acquire("debug:kernel:pid=42", "peer-A", wait_s=0)
    assert isinstance(h, LeaseHandle)
    async with h:
        assert mgr.who_holds("debug:kernel:pid=42") == "peer-A"
    assert mgr.who_holds("debug:kernel:pid=42") is None
