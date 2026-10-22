"""MCP wire — whoami / list_peers / bp_manage ownership.

Split out of test_multi_agent.py; server wiring lives in _multi_fakes.
"""

from __future__ import annotations

from _multi_fakes import _build_ctx_and_server, _call_as


async def test_whoami_reports_bound_client_id(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call_as("peer-A", server, "target_manage", {"action": "whoami"})
    assert body["client_id"] == "peer-A"
    body = await _call_as("peer-B", server, "target_manage", {"action": "whoami"})
    assert body["client_id"] == "peer-B"


async def test_list_peers_reflects_connected_callers(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # Two callers connect to kernel — peer-B joins as co-owner.
    resp_a = await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    assert resp_a.get("shared") is False
    assert resp_a.get("primary_owner") == "peer-A"
    resp_b = await _call_as("peer-B", server, "target_manage", {"action": "connect"})
    assert resp_b.get("shared") is True
    assert resp_b.get("primary_owner") == "peer-A"
    peers = await _call_as("peer-A", server, "target_manage", {"action": "list_peers"})
    ids = {p["client_id"] for p in peers.get("peers", [])}
    assert {"peer-A", "peer-B"} <= ids


async def test_bp_add_attributes_ownership_and_refuses_foreign(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    await _call_as("peer-B", server, "target_manage", {"action": "connect"})

    add_a = await _call_as("peer-A", server, "bp_manage",
                            {"action": "add", "kind": "sw", "address": "0x401000"})
    bp_a = add_a["bp_id"]
    add_b = await _call_as("peer-B", server, "bp_manage",
                            {"action": "add", "kind": "sw", "address": "0x402000"})
    bp_b = add_b["bp_id"]

    # list from peer-A: their own bp is not foreign; peer-B's is
    listing = await _call_as("peer-A", server, "bp_manage", {"action": "list"})
    rows = {r["bp_id"]: r for r in listing["breakpoints"]}
    assert rows[bp_a]["owner"] == "peer-A" and rows[bp_a]["foreign"] is False
    assert rows[bp_b]["owner"] == "peer-B" and rows[bp_b]["foreign"] is True

    # peer-A can't remove peer-B's bp without force
    refused = await _call_as("peer-A", server, "bp_manage",
                              {"action": "remove", "bp_id": bp_b})
    assert refused["ok"] is False
    assert refused["kind"] == "foreign_owned"
    assert refused["owner"] == "peer-B"

    # with force it goes through
    forced = await _call_as("peer-A", server, "bp_manage",
                             {"action": "remove", "bp_id": bp_b, "force": True})
    assert forced.get("ok") is True

    # peer-B removing their own bp (already gone) still succeeds shape-wise
    # for peer-A's own bp, remove succeeds without force
    own = await _call_as("peer-A", server, "bp_manage",
                          {"action": "remove", "bp_id": bp_a})
    assert own.get("ok") is True
