"""ownership.py — OwnershipRegistry claim/annotate/release semantics.

Split out of test_multi_agent.py.
"""

from __future__ import annotations

from suspex.ownership import OwnershipRegistry


async def test_ownership_claim_and_owner_of() -> None:
    reg = OwnershipRegistry()
    await reg.claim("bp:kernel", "42", "peer-A")
    assert await reg.owner_of("bp:kernel", "42") == "peer-A"
    # idempotent same-owner claim
    await reg.claim("bp:kernel", "42", "peer-A")
    assert await reg.owner_of("bp:kernel", "42") == "peer-A"
    # different-owner claim does NOT steal
    await reg.claim("bp:kernel", "42", "peer-B")
    assert await reg.owner_of("bp:kernel", "42") == "peer-A"


async def test_ownership_is_foreign_or_none() -> None:
    reg = OwnershipRegistry()
    assert await reg.is_foreign_or_none("bp:kernel", "42", "peer-A") is None
    await reg.claim("bp:kernel", "42", "peer-A")
    assert await reg.is_foreign_or_none("bp:kernel", "42", "peer-A") is False
    assert await reg.is_foreign_or_none("bp:kernel", "42", "peer-B") is True


async def test_ownership_annotate_stamps_owner_foreign() -> None:
    reg = OwnershipRegistry()
    await reg.claim("bp:kernel", "10", "peer-A")
    await reg.claim("bp:kernel", "11", "peer-B")
    rows = [{"bp_id": "10"}, {"bp_id": "11"}, {"bp_id": "12"}]
    await reg.annotate("bp:kernel", rows, "bp_id", "peer-A")
    assert rows[0]["owner"] == "peer-A" and rows[0]["foreign"] is False
    assert rows[1]["owner"] == "peer-B" and rows[1]["foreign"] is True
    assert rows[2]["owner"] is None and rows[2]["foreign"] is None


async def test_ownership_release_by_owner() -> None:
    reg = OwnershipRegistry()
    await reg.claim("bp:kernel", "10", "peer-A")
    await reg.claim("bp:kernel", "11", "peer-A")
    await reg.claim("bp:kernel", "12", "peer-B")
    await reg.release_by_owner("peer-A")
    assert await reg.owner_of("bp:kernel", "10") is None
    assert await reg.owner_of("bp:kernel", "11") is None
    assert await reg.owner_of("bp:kernel", "12") == "peer-B"
