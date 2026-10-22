from pathlib import Path

from suspex.config import SuspexConfig, load_config


def test_defaults() -> None:
    cfg = SuspexConfig()
    assert cfg.target.port == 50074
    assert cfg.mcp.bind == "127.0.0.1"
    assert cfg.security.authorized_targets


def test_load_example_yaml() -> None:
    example = Path(__file__).resolve().parents[2] / "configs" / "example.yaml"
    cfg = load_config(example)
    assert cfg.target.host == "192.168.56.10"
    assert cfg.target.port == 50074
    assert cfg.target.token == "change-me-long-random"
    assert "192.168.56.0/24" in cfg.security.authorized_targets
    assert cfg.mcp.port == 8765
    assert cfg.dashboard.port == 8766
    assert cfg.ida.enabled is True
    assert any("idalib-mcp" in c for c in cfg.ida.command)


def test_unknown_keys_ignored(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("target:\n  port: 1234\n  bogus_key: 1\nunknown_top: x\n")
    cfg = load_config(p)
    assert cfg.target.port == 1234
    assert not hasattr(cfg.target, "bogus_key")


def test_endpoint() -> None:
    cfg = SuspexConfig()
    assert cfg.target_endpoint == "127.0.0.1:50074"


def test_example_yaml_has_user_target() -> None:
    example = Path(__file__).resolve().parents[2] / "configs" / "example.yaml"
    cfg = load_config(example)
    assert "user" in cfg.targets
    assert cfg.targets["user"].port == 50075
    assert cfg.target_for("user").port == 50075
    assert cfg.target_for("kernel") is cfg.target
