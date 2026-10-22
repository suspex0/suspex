"""Parity harness logic against fake kernel/usermode clients."""

from __future__ import annotations

from suspex.parity import MEM_COMMIT, format_report, run_parity, verdict

REGION_BYTES = 0x10000
REGIONS = [
    {"base": hex(0x10000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x04, "type": 0x20000, "module": ""},
    {"base": hex(0x20000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x20, "type": 0x20000, "module": "foo.dll"},
    {"base": hex(0x30000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x01, "type": 0x20000, "module": ""},  # PAGE_NOACCESS
    {"base": hex(0x40000), "size": REGION_BYTES, "state": 0x2000,  # MEM_RESERVE
     "protect": 0, "type": 0, "module": ""},
]


def _region_bytes(seed: int, size: int = REGION_BYTES) -> bytes:
    return bytes((seed * 31 + i) % 251 for i in range(size))


class FakeClient:
    """Serves the shared region map plus deterministic page-backed data.

    fail_pages: raise on reads whose containing 64k page is listed.
    xor: invert every served byte (guaranteed mismatch at any offset).
    """

    def __init__(self, data: dict[int, bytes], fail_pages: set[int] | None = None,
                 xor: bool = False) -> None:
        self.data = data
        self.fail_pages = fail_pages or set()
        self.xor = xor

    async def debug_regions(self, pid: int) -> list[dict]:
        return REGIONS

    async def mem_read(self, pid: int, address: int, size: int, space: str = "user") -> bytes:
        page = address & ~0xFFFF
        if page in self.fail_pages:
            raise RuntimeError(f"fake read failure on page {hex(page)}")
        blob = self.data[page]
        off = address - page
        chunk = blob[off : off + size]
        return bytes(b ^ 0xFF for b in chunk) if self.xor else chunk


def _setup() -> tuple[FakeClient, dict[int, bytes]]:
    data = {0x10000: _region_bytes(1), 0x20000: _region_bytes(2)}
    return FakeClient(data), data


async def test_zero_mismatch_parity() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data), pid=42, samples=4, read_bytes=512)
    s = report["summary"]
    assert s["regions_total"] == 4
    assert s["regions_committed"] == 2  # no-access + reserved regions filtered
    assert s["samples"] == 2
    assert s["compared"] == 2
    assert s["mismatches"] == 0
    assert s["both_failed"] == 0
    assert s["bytes_compared"] == 2 * 512
    assert verdict(report)[0] == "info"


async def test_mismatch_detected_with_offsets() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data, xor=True), pid=42, samples=8,
                              read_bytes=1024, seed=7)
    s = report["summary"]
    assert s["mismatches"] == 2  # every sampled region is xor-corrupted
    assert s["matches"] == 0
    for bad in [c for c in report["checks"] if c.get("match") is False]:
        assert bad["mismatch_count"] == 1024
        assert len(bad["mismatch_offsets"]) == 32  # capped
        assert bad["kernel_sha256"] != bad["user_sha256"]
    assert verdict(report)[0] == "high"


async def test_error_asymmetry_counted() -> None:
    kernel, data = _setup()
    kernel.fail_pages = {0x10000}
    report = await run_parity(kernel, FakeClient(data), pid=42, samples=4, read_bytes=256)
    s = report["summary"]
    assert s["user_ok_kernel_failed"] == 1
    assert s["kernel_ok_user_failed"] == 0
    assert verdict(report)[0] == "warning"


async def test_both_failed_is_high_verdict() -> None:
    kernel, data = _setup()
    report = await run_parity(FakeClient(data, fail_pages={0x10000, 0x20000}),
                              FakeClient(data, fail_pages={0x10000, 0x20000}),
                              pid=42, samples=4, read_bytes=256)
    s = report["summary"]
    assert s["both_failed"] == 2
    assert s["compared"] == 0
    assert verdict(report)[0] == "high"


async def test_kuser_shared_data_skipped_as_volatile() -> None:
    data = {
        0x10000: _region_bytes(1),
        0x7FFE0000: _region_bytes(7, 0x1000),  # KUSER_SHARED_DATA page
    }
    regions = REGIONS[:2] + [
        {"base": hex(0x7FFE0000), "size": 0x1000, "state": MEM_COMMIT,
         "protect": 0x02, "type": 0, "module": ""},
    ]
    kernel = FakeClient(data, )
    user = FakeClient(data)

    async def regions_fn(pid: int) -> list[dict]:
        return regions

    kernel.debug_regions = regions_fn
    user.debug_regions = regions_fn
    report = await run_parity(kernel, user, pid=42, samples=8, read_bytes=256, seed=1)
    s = report["summary"]
    assert s["volatile_skipped"] == 1
    assert s["mismatches"] == 0
    assert s["compared"] == 1
    assert verdict(report)[0] == "info"
    assert any("KUSER_SHARED_DATA" in c.get("note", "") for c in report["checks"])


async def test_sample_offsets_deterministic() -> None:
    kernel, data = _setup()
    user = FakeClient(data)
    r1 = await run_parity(kernel, user, pid=42, samples=4, read_bytes=128, seed=3)
    r2 = await run_parity(kernel, user, pid=42, samples=4, read_bytes=128, seed=3)
    assert [c["address"] for c in r1["checks"]] == [c["address"] for c in r2["checks"]]


async def test_format_report_mentions_failures() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data, xor=True), pid=42, samples=8,
                              read_bytes=1024, seed=1)
    text = format_report(report)
    assert "2 MISMATCH" in text
    assert "MISMATCH count=1024" in text
