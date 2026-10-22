import pytest

from suspex.config import SuspexConfig
from suspex.session import Session


@pytest.fixture()
def session() -> Session:
    return Session(SuspexConfig())


def test_require_client_raises_when_disconnected(session: Session) -> None:
    with pytest.raises(RuntimeError, match="not connected"):
        session.require_client()


def test_delete_gated_by_default(session: Session) -> None:
    # trash-safe delete stays available by default
    session.assert_allowed("file_manage", "delete", {"no_trash": False})
    with pytest.raises(PermissionError):
        session.assert_allowed("file_manage", "delete", {"no_trash": True})


def test_delete_allowed_when_configured() -> None:
    cfg = SuspexConfig()
    cfg.security.allow_delete = True
    s = Session(cfg)
    s.assert_allowed("file_manage", "delete")


def test_driver_ops_gating() -> None:
    cfg = SuspexConfig()
    cfg.security.allow_driver_unload = False
    s = Session(cfg)
    with pytest.raises(PermissionError):
        s.assert_allowed("target_manage", "driver_unload")
    s.assert_allowed("target_manage", "driver_load")


def test_tool_log_destructive_flags(session: Session) -> None:
    call = session.record_tool_call("file_manage", "delete", ok=False, error="gated")
    assert call.destructive is True
    other = session.record_tool_call("mem_rw", "read")
    assert other.destructive is False
    assert len(session.tool_log) == 2
