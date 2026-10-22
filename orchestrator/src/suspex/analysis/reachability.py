"""Evidence-honest reachability — the reporting contract every analysis
pass in this package uses.

The rule (ported from knife): a pass may report what it *proved*
(ConfirmedDirect / ConfirmedIndirect), what it *could not prove*
(Unresolved), or what it never saw (NotObserved). It must never claim a
site is unreachable — indirect dispatch is always outside a static graph.
"""

from __future__ import annotations

from enum import Enum


class Reachability(str, Enum):
    """How firmly an analysis pass established that a site can be driven."""

    CONFIRMED_DIRECT = "confirmed_direct"
    """Call site sits in a function reachable by direct edges from roots."""

    CONFIRMED_INDIRECT = "confirmed_indirect"
    """Reachable, but only through at least one indirect edge."""

    UNRESOLVED = "unresolved"
    """The pass could not prove reachability either way. NEVER means
    'unreachable' — callers must treat this as 'unknown'."""

    NOT_OBSERVED = "not_observed"
    """Expected evidence was not present in the analyzed image at all."""


def row(site: int, reachability: Reachability, provenance: str,
        **extra) -> dict:
    """Uniform result row for passes that report reachability.

    ``provenance`` is a short SHOUTED_SNAKE audit trail naming the evidence
    chain that produced the verdict (e.g.
    ``"DIRECT_ARGUMENT_STATIC_FUNCTION_AND_MATCHED_DPC_ACTIVATION"``).
    """
    out = {
        "site": site,
        "site_hex": f"0x{site:X}",
        "reachability": reachability.value,
        "provenance": provenance,
    }
    out.update(extra)
    return out
