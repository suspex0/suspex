import pytest

from suspex.allowlist import TargetNotAllowed, check_authorized, resolve_host


def test_loopback_allowed_by_default() -> None:
    assert check_authorized("127.0.0.1", ["127.0.0.0/8"]) == "127.0.0.1"


def test_cidr_match() -> None:
    assert check_authorized("192.168.56.10", ["192.168.56.0/24"]) == "192.168.56.10"


def test_outside_cidr_refused() -> None:
    with pytest.raises(TargetNotAllowed):
        check_authorized("8.8.8.8", ["192.168.56.0/24"])


def test_unresolvable_refused() -> None:
    with pytest.raises(TargetNotAllowed):
        check_authorized("this-host-does-not-exist.invalid", ["0.0.0.0/0"])


def test_hostname_resolution() -> None:
    # localhost resolves into the loopback allowlist on any Windows host
    addr = check_authorized("localhost", ["127.0.0.0/8", "::1/128"])
    assert addr in ("127.0.0.1", "::1")


def test_resolve_host_returns_string() -> None:
    assert resolve_host("127.0.0.1") == "127.0.0.1"
