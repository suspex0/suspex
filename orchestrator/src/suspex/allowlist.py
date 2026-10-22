"""Target allowlist enforcement: connect is refused unless the target's
resolved address falls inside authorized_targets CIDRs. Runs before any
packet leaves the orchestrator."""

from __future__ import annotations

import ipaddress
import socket


class TargetNotAllowed(Exception):
    pass


def resolve_host(host: str) -> str:
    """Resolve a host to its first IPv4/IPv6 address string.

    Raises TargetNotAllowed for unresolvable hosts.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"cannot resolve target host {host!r}: {exc}") from exc
    for family, _type, _proto, _canonname, sockaddr in infos:
        return str(sockaddr[0])
    raise TargetNotAllowed(f"no addresses for {host!r}")


def check_authorized(host: str, authorized_cidrs: list[str]) -> str:
    """Return the resolved address, or raise TargetNotAllowed."""
    addr_str = host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        addr_str = resolve_host(host)

    addr = ipaddress.ip_address(addr_str)
    for cidr in authorized_cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if addr in net:
            return addr_str
    raise TargetNotAllowed(
        f"target {host} ({addr_str}) is not in authorized_targets {authorized_cidrs}"
    )
