"""Mocked test for ``emulate.seed_from_target``.

Verifies the sequence of mem_read + debug_regs calls the seed action
makes, and that the resulting emulator state carries the seeded
registers + hydrated memory. No live target, no gRPC.
"""
from __future__ import annotations

import pytest

from suspex import codegen as cg
from suspex import emulate as em


pytestmark = pytest.mark.skipif(
    not cg.unicorn_available(),
    reason="unicorn not installed",
)


class _StubClient:
    """Minimal client implementing the surface `seed_from_target` reaches."""

    def __init__(self) -> None:
        # (pid, addr, size, view) -> bytes
        self.memory: dict[tuple[int, int, int, str], bytes] = {}
        # Recorded call log so tests can assert the order.
        self.calls: list[tuple[str, tuple, dict]] = []
        # tid -> reg dict
        self.regs: dict[int, dict[str, int]] = {}

    def prime_region(self, pid: int, addr: int, size: int, view: str,
                      data: bytes) -> None:
        self.memory[(pid, addr, size, view)] = data

    def prime_regs(self, tid: int, regs: dict[str, int]) -> None:
        self.regs[tid] = regs

    async def mem_read(self, pid, addr, size, view,
                        allow_fault=False, partial=False, want_meta=False,
                        timeout=None):
        self.calls.append(("mem_read", (pid, addr, size, view),
                            {"allow_fault": allow_fault,
                             "partial": partial,
                             "want_meta": want_meta}))
        key = (pid, addr, size, view)
        data = self.memory.get(key)
        if data is None:
            # Emulate an unmapped region: return an empty read + meta so
            # the seed helper knows to log a hole rather than hydrate.
            return (b"", {"read_bytes": 0, "first_bad_offset": 0}) if want_meta else b""
        if want_meta:
            return data, {"read_bytes": len(data), "first_bad_offset": 0}
        return data

    async def debug_regs(self):
        # Real contract: GetRegsRequest has no thread selector — the
        # agent reports the debugged context for the attached session.
        self.calls.append(("debug_regs", (), {}))
        return dict(self.regs.get(5678, {}))


@pytest.mark.asyncio
async def test_seed_pulls_regs_and_memory() -> None:
    s = em.create_session(arch="x64", engine="unicorn")
    client = _StubClient()
    client.prime_region(1234, 0x7FF600000000, 0x1000, "user", b"IMAGE" + b"\x00" * (0x1000 - 5))
    client.prime_region(1234, 0x2000, 0x1000, "user", b"HEAP" + b"\x00" * (0x1000 - 4))
    client.prime_regs(5678, {"rax": 0x1, "rip": 0x7FF600000000, "rsp": 0x10000})

    result = await em.seed_from_target(
        s, client=client,
        view="user", pid=1234, tid=5678,
        regions=[{"address": "0x7ff600000000", "size": 0x1000, "label": "image"},
                 {"address": 0x2000, "size": 0x1000, "label": "heap"}],
    )

    # The seed helper must issue two mem_reads AND a debug_regs.
    op_names = [c[0] for c in client.calls]
    assert op_names.count("mem_read") == 2
    assert "debug_regs" in op_names

    assert result["ok"] is True
    assert result["regions_loaded"] == 2
    assert result["bytes_seeded"] == 0x2000
    assert result["cursor"] == hex(0x7FF600000000)

    # Memory hydrated into the emulator?
    got = s.engine.mem_read(0x7FF600000000, 5)
    assert got == b"IMAGE"
    got = s.engine.mem_read(0x2000, 4)
    assert got == b"HEAP"
    # Regs written?
    regs = s.engine.read_regs()
    assert regs["rax"] == 1
    assert regs["rip"] == 0x7FF600000000
    # Cursor moved to rip.
    assert s.cursor == 0x7FF600000000

    em.close_session(s.id)


@pytest.mark.asyncio
async def test_seed_records_holes() -> None:
    s = em.create_session(arch="x64", engine="unicorn")
    client = _StubClient()
    # Only prime one region; the other returns empty.
    client.prime_region(1234, 0x4000, 0x1000, "user", b"OK" + b"\x00" * (0x1000 - 2))
    client.prime_regs(5678, {"rip": 0x4000})

    result = await em.seed_from_target(
        s, client=client, view="user", pid=1234, tid=5678,
        regions=[{"address": 0x4000, "size": 0x1000, "label": "good"},
                 {"address": 0x9000, "size": 0x1000, "label": "unmapped"}],
    )

    assert result["ok"] is True
    assert result["regions_loaded"] == 1  # only one region actually had data
    assert result["bytes_seeded"] == 0x1000
    # A hole was reported for the unmapped region.
    assert any(h.get("address") == hex(0x9000) for h in result["holes"])

    em.close_session(s.id)
