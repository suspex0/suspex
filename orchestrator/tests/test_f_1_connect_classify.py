"""v0.17 F-1a + F-1b — net-layer HINT_RULES + Session.connect pre-flight probe.

The regex classifiers turn raw OS-level socket error strings (``WSAEACCES``,
``WSAETIMEDOUT``, ``WSAECONNREFUSED``, ``WSAEHOSTUNREACH``, ``WSAENETUNREACH``)
into stable ``kind`` slugs the caller can branch on. The pre-flight probe
(``session._probe_tcp``) surfaces those OS errors *before* gRPC's opaque
``UNAVAILABLE`` swallows them, so the classifier actually gets to fire.
"""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest

from suspex.mcp._error_enrich import HINT_RULES, classify, enrich_error
from suspex.session import _probe_tcp


# --------------------------------------------------------------------------- #
# F-1a — net-layer regex classifiers
# --------------------------------------------------------------------------- #


def test_f_1a_wsaeacces_classifies_connect_blocked():
    kind, hint = classify("WSAEACCES tcp probe to 10.0.0.5:50074 failed")
    assert kind == "connect_blocked"
    assert "firewall" in hint


def test_f_1a_wsaetimedout_classifies_connect_timeout():
    kind, hint = classify("WSAETIMEDOUT tcp probe to 10.0.0.5:50074 failed")
    assert kind == "connect_timeout"
    assert "SYN" in hint or "agent" in hint


def test_f_1a_wsaeconnrefused_classifies_connect_refused():
    kind, hint = classify("WSAECONNREFUSED tcp probe to 10.0.0.5:50074 failed")
    assert kind == "connect_refused"
    assert "listening" in hint or "agent" in hint


def test_f_1a_wsaehostunreach_classifies_host_unreachable():
    kind, hint = classify("WSAEHOSTUNREACH tcp probe to 10.0.0.5:50074 failed")
    assert kind == "host_unreachable"
    assert "route" in hint or "VPN" in hint


def test_f_1a_wsaenetunreach_classifies_network_unreachable():
    kind, hint = classify("WSAENETUNREACH tcp probe to 10.0.0.5:50074 failed")
    assert kind == "network_unreachable"


def test_f_1a_posix_connection_refused_classifies_connect_refused():
    """Non-Windows string form still classifies for cross-platform triage."""
    kind, _hint = classify("ECONNREFUSED: connection refused")
    assert kind == "connect_refused"


def test_f_1a_generic_channel_unavailable_still_wins_when_no_net_tag():
    """Order sanity check: adding net rules did NOT accidentally shadow the
    generic gRPC UNAVAILABLE catch-all when the message has no socket tag."""
    kind, _hint = classify("StatusCode.UNAVAILABLE channel is closed")
    assert kind == "channel_unavailable"


def test_f_1a_partial_read_still_fires_after_net_rules_added():
    """Ordering guard: partial_read still classifies correctly after net
    rules were inserted mid-file."""
    kind, _hint = classify("driver: DeviceIoControl gle=299")
    assert kind == "partial_read"


def test_f_1a_enrich_error_pipeline_preserves_kind_for_wsae():
    """Full pipeline sanity — enrich_error emits kind + hint for net errors."""
    out = enrich_error("target_manage", "connect",
                      "WSAECONNREFUSED tcp probe to 127.0.0.1:65535 failed")
    assert out["kind"] == "connect_refused"
    assert out.get("hint")


# --------------------------------------------------------------------------- #
# F-1b — pre-flight TCP probe
# --------------------------------------------------------------------------- #


def _closed_port() -> int:
    """Bind a socket to get an ephemeral port, then close it. The port is
    (almost certainly) unbound afterwards so a connect probe returns
    WSAECONNREFUSED on Windows / ECONNREFUSED on POSIX."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_f_1b_probe_raises_rich_oserror_for_refused_port():
    """A closed loopback port -> OSError whose string carries a tag the
    classifier fires on."""
    port = _closed_port()

    async def go():
        with pytest.raises(OSError) as exc:
            await _probe_tcp("127.0.0.1", port, timeout_s=1.0)
        return exc.value

    err = asyncio.new_event_loop().run_until_complete(go())
    msg = str(err)
    # The rich message must include a symbolic net-error tag (WSAExxxx on
    # Windows, ECONNxxxx on POSIX, or a socket.timeout mapped to WSAETIMEDOUT)
    # so the regex classifiers key off a stable token, not raw strerror text.
    assert any(t in msg for t in
               ("WSAE", "ECONN", "EHOST", "ENET", "EACCES", "errno=")), msg
    assert "127.0.0.1" in msg
    kind, _hint = classify(msg)
    # On Windows loopback the closed-port probe may either be refused
    # immediately (WSAECONNREFUSED) or hit the socket-level timeout
    # (WSAETIMEDOUT). Either way we resolve to a specific slug, not the
    # generic channel_unavailable catch-all.
    assert kind in {"connect_refused", "connect_blocked", "connect_timeout",
                    "host_unreachable", "network_unreachable"}, (
        f"pre-flight probe error did not classify: kind={kind} msg={msg!r}"
    )


def test_f_1b_probe_succeeds_against_listening_socket():
    """Sanity check the happy path — a bound listener on loopback."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    _, port = listener.getsockname()

    async def go():
        try:
            await _probe_tcp("127.0.0.1", port, timeout_s=1.0)
        finally:
            listener.close()

    asyncio.new_event_loop().run_until_complete(go())


def test_f_1b_probe_short_timeout_returns_promptly():
    """Timeout budget honored: unroutable host raises within the deadline."""
    # 192.0.2.x is TEST-NET-1 (RFC 5737) — reserved for documentation, not
    # routed. connect() should stall until the timeout fires.
    async def go():
        with pytest.raises(OSError):
            await _probe_tcp("192.0.2.1", 50074, timeout_s=0.5)

    import time as _t
    loop = asyncio.new_event_loop()
    started = _t.monotonic()
    try:
        loop.run_until_complete(go())
    finally:
        loop.close()
    # Give generous slack for slow CI machines but ensure we're not
    # actually waiting the full OS-level SYN timeout (~20s on Windows).
    assert _t.monotonic() - started < 5.0
