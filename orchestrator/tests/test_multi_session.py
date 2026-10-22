"""session.py — refcount + owner + release_by_owner.

Split out of test_multi_agent.py; fakes and fixture live in _multi_fakes.
"""

from __future__ import annotations

from suspex.config import SuspexConfig, TargetConfig
from suspex.session import Session

from _multi_fakes import fake_agent_class  # noqa: F401  (pytest fixture)


def _view_key(s: Session, kind: str) -> str:
    """Multi-machine: view keys are '<machine>.<kind>'; tests don't care
    which machine label was learned — find the connected view by kind."""
    for k in s.clients:
        if k == kind or k.endswith(f".{kind}"):
            return k
    raise AssertionError(f"no connected {kind!r} view in {sorted(s.clients)}")


async def test_session_connect_stamps_owner_and_refcount(fake_agent_class) -> None:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    s = Session(cfg)
    status = await s.connect(owner="peer-A")
    assert status["shared"] is False
    assert status["primary_owner"] == "peer-A"
    k = _view_key(s, "kernel")
    assert s.owners[k] == "peer-A"
    assert s.refs[k] == {"peer-A": 1}


async def test_session_connect_peer_shared(fake_agent_class) -> None:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    s = Session(cfg)
    await s.connect(owner="peer-A")
    status = await s.connect(owner="peer-B")
    assert status["shared"] is True
    assert status["primary_owner"] == "peer-A"
    assert s.refs[_view_key(s, "kernel")] == {"peer-A": 1, "peer-B": 1}


async def test_session_disconnect_owner_refcount(fake_agent_class) -> None:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    s = Session(cfg)
    await s.connect(owner="peer-A")
    await s.connect(owner="peer-B")
    k = _view_key(s, "kernel")
    out = await s.disconnect(owner="peer-A")
    assert out["disconnected"] == []  # not the last owner, no actual close
    assert k in out["partial_release"]
    # peer-B still owns it
    assert s.clients.get(k) is not None
    out = await s.disconnect(owner="peer-B")
    assert out["disconnected"] == [k]
    assert s.clients == {}


async def test_session_force_takeover_closes_prior(fake_agent_class) -> None:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    s = Session(cfg)
    await s.connect(owner="peer-A")
    k = _view_key(s, "kernel")
    prior = s.clients[k]
    status = await s.connect(owner="peer-B", force=True)
    assert status.get("forced_takeover") is True
    assert prior._closed is True
    assert s.owners[k] == "peer-B"


async def test_session_release_by_owner(fake_agent_class) -> None:
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.targets["user"] = TargetConfig(host="127.0.0.1", port=2)
    s = Session(cfg)
    await s.connect(name="kernel", owner="peer-A")
    await s.connect(name="user", owner="peer-A")
    await s.connect(name="kernel", owner="peer-B")
    released = await s.release_by_owner("peer-A")
    # kernel had two owners so peer-A leaving leaves it up; user was sole owner so it closes
    assert len(released) == 1 and released[0].endswith(".user")
    assert _view_key(s, "kernel") in s.clients
    assert not any(k == "user" or k.endswith(".user") for k in s.clients)
