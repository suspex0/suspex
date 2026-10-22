import pytest

from suspex.config import SuspexConfig, TargetConfig, load_config
from suspex.session import Session


def test_target_for_primary_fallback() -> None:
    cfg = SuspexConfig()
    assert cfg.target_for("kernel") is cfg.target
    assert cfg.target_for(None) is cfg.target
    assert cfg.target_for("") is cfg.target


def test_target_for_unknown_raises() -> None:
    cfg = SuspexConfig()
    with pytest.raises(KeyError):
        cfg.target_for("nope")


def test_target_for_named_secondary() -> None:
    cfg = SuspexConfig()
    cfg.targets["user"] = TargetConfig(port=50075)
    assert cfg.target_for("user").port == 50075
    assert cfg.target_for("kernel") is cfg.target


def test_load_config_targets(tmp_path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(
        "target:\n  port: 50074\ntargets:\n  user:\n    port: 50075\n"
        "    token: um-token\n"
    )
    cfg = load_config(p)
    assert set(cfg.targets) == {"user"}
    assert cfg.targets["user"].port == 50075
    assert cfg.targets["user"].token == "um-token"
    assert cfg.target.port == 50074


def test_client_property_defaults_to_primary() -> None:
    s = Session(SuspexConfig())
    assert s.client is None
    assert s.connected is False
    assert s.primary == "kernel"


def test_require_client_named_raises_when_missing() -> None:
    s = Session(SuspexConfig())
    with pytest.raises(RuntimeError, match="user"):
        s.require_client("user")
    with pytest.raises(RuntimeError, match="kernel"):
        s.require_client()


def test_disconnect_noop_returns_empty_list() -> None:
    s = Session(SuspexConfig())

    async def go() -> None:
        result = await s.disconnect()
        assert result == {"ok": True, "disconnected": []}

    import asyncio

    asyncio.run(go())
