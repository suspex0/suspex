"""Tests for AgentClient concurrency behaviour (does NOT open a gRPC
channel — we monkey-patch _call to exercise the semaphore directly)."""

from __future__ import annotations

import asyncio

import pytest

from suspex.agent_client import AgentClient


def _make_client(max_inflight: int) -> AgentClient:
    # Never connect: we only exercise the semaphore + _inflight_count around
    # a synthetic coroutine. Real gRPC channel construction is deferred to
    # connect().
    return AgentClient("127.0.0.1", 1, "", timeout_ms=1000,
                       max_inflight=max_inflight)


def test_defaults_expose_semaphore() -> None:
    c = AgentClient("127.0.0.1", 1, "")
    assert c._max_inflight == 16
    assert isinstance(c._sem, asyncio.Semaphore)
    assert c._inflight_count == 0


def test_ctor_accepts_custom_cap() -> None:
    c = _make_client(4)
    assert c._max_inflight == 4


async def test_call_caps_concurrency_at_max_inflight() -> None:
    """Fan out 20 concurrent _call attempts through the semaphore with a
    monkey-patched RPC; assert we never see more than max_inflight
    coroutines inside the critical section at once."""
    cap = 4
    client = _make_client(cap)
    gate = asyncio.Event()
    peak = 0
    active = 0
    lock = asyncio.Lock()

    async def fake_rpc(_request, metadata=None, timeout=None):  # noqa: ARG001
        nonlocal peak, active
        async with lock:
            active += 1
            if active > peak:
                peak = active
        try:
            await gate.wait()
        finally:
            async with lock:
                active -= 1
        return "ok"

    # Give the fake RPC a __qualname__ so the recent-ops entry has a method
    # name; matches how real grpc stub methods look.
    fake_rpc.__qualname__ = "FakeStub.Call"

    async def worker() -> str:
        return await client._call(fake_rpc, object())

    tasks = [asyncio.create_task(worker()) for _ in range(20)]
    # Let workers pile up on the semaphore before we release them.
    await asyncio.sleep(0.1)
    gate.set()
    results = await asyncio.gather(*tasks)

    assert all(r == "ok" for r in results)
    assert peak <= cap, f"peak concurrency {peak} exceeded cap {cap}"
    # Counter must unwind cleanly.
    assert client._inflight_count == 0


async def test_recent_ops_records_inflight_snapshot() -> None:
    """The recent-ops ring should carry inflight_at_start / max_inflight so
    operators can see contention when a call goes wrong."""
    client = _make_client(2)

    async def fake_rpc(_request, metadata=None, timeout=None):  # noqa: ARG001
        return "ok"

    fake_rpc.__qualname__ = "FakeStub.Call"

    await client._call(fake_rpc, object())
    ops = client.recent_ops()
    assert ops, "expected at least one recorded op"
    last = ops[-1]
    assert last["status"] == "ok"
    assert last["max_inflight"] == 2
    # First call was made from a quiet client — inflight was 0 at entry.
    assert last["inflight_at_start"] == 0


async def test_semaphore_releases_on_exception() -> None:
    """A failing RPC must still release the semaphore, or bulk sweeps
    would deadlock the client after the first error."""
    cap = 2
    client = _make_client(cap)

    async def bad_rpc(_request, metadata=None, timeout=None):  # noqa: ARG001
        raise RuntimeError("boom")

    bad_rpc.__qualname__ = "FakeStub.Bad"

    for _ in range(5):
        with pytest.raises(RuntimeError, match="boom"):
            await client._call(bad_rpc, object())
    # Counter must not leak on the error path.
    assert client._inflight_count == 0
    # The semaphore should be fully available again.
    for _ in range(cap):
        assert client._sem.locked() is False


async def test_call_raises_labelled_error_when_stub_returns_none() -> None:
    """v0.16: guard against a stub whose awaitable resolves to None.
    Previously downstream methods like handle_list crashed with an
    AttributeError on `msg.status.ok`; the guard raises a labelled
    RuntimeError instead so recent_ops and the caller see the same
    story."""
    client = _make_client(2)

    async def none_rpc(_request, metadata=None, timeout=None):  # noqa: ARG001
        return None

    none_rpc.__qualname__ = "MemoryStub.HandleList"

    with pytest.raises(RuntimeError, match="MemoryStub.HandleList returned no message"):
        await client._call(none_rpc, object())
    # The failure is also recorded in the ring so recent_ops can surface it.
    ops = client.recent_ops()
    assert ops[-1]["status"] == "error"
    assert "returned no message" in ops[-1]["error"]
    # Counter must not leak.
    assert client._inflight_count == 0


async def test_mem_write_threads_allow_map_write() -> None:
    """C.1: the physical-write opt-in must reach MemoryWriteRequest, and
    stay off by default (the v5 driver refuses un-flagged physical writes).
    v12: the wrapper returns {"written_bytes", "write_path"} — the fake
    response carries a direct_va path to exercise the string map."""
    from suspex.generated import suspex_pb2 as pb

    client = _make_client(2)
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["rpc"] = rpc
        captured["req"] = req

        class _Resp:
            written_bytes = len(req.data)
            write_path = 1  # SUSPEX_MEM_WRITE_PATH_DIRECT_VA

            class status:
                ok = True
                error = ""

        return _Resp()

    client._call = fake_call  # type: ignore[method-assign]
    # connect() is what normally creates the service stubs; stand in a bare
    # holder so mem_write can resolve .Write without opening a channel.
    client.memory = type("_MemoryStub", (), {"Write": object()})()

    res = await client.mem_write(0, 0x1000, b"12345", "user")
    assert res == {"written_bytes": 5, "write_path": "direct_va"}
    assert captured["req"].space == pb.USER
    assert captured["req"].allow_map_write is False

    res = await client.mem_write(0, 0x1000, b"12345", "physical", allow_map_write=True)
    assert res["written_bytes"] == 5
    assert captured["req"].space == pb.PHYSICAL
    assert captured["req"].allow_map_write is True


async def test_file_dump_module_threads_kernel(tmp_path) -> None:
    """The kernel flag must reach DumpModuleRequest, and header notes must
    survive the stream (kernel dumps carry the PAGE/INIT-zeroed caveat)."""
    from suspex.generated import suspex_pb2 as pb

    client = _make_client(2)

    class _FakeFiles:
        req = None

        def DumpModule(self, req, metadata=None):  # noqa: ARG002
            type(self).req = req

            async def gen():
                yield pb.DownloadChunk(
                    header=pb.DownloadHeader(size=3, notes="kernel VA dump"))
                yield pb.DownloadChunk(data=b"abc")

            return gen()

    client.files = _FakeFiles()
    dest = tmp_path / "ntoskrnl.exe"
    out = await client.file_dump_module(0, "ntoskrnl.exe", str(dest), kernel=True)

    assert _FakeFiles.req.kernel is True
    assert out["bytes"] == 3
    assert out["notes"] == "kernel VA dump"
    assert dest.read_bytes() == b"abc"


async def test_host_info_gracefully_degrades_on_old_agent() -> None:
    """A v7 orchestrator against a v7 agent (no HostInfo RPC) must return
    a clean ok:false envelope, not raise or wedge. The client detects
    absence by hasattr on the stub."""
    client = _make_client(2)

    # Stand in a bare agent stub with NO HostInfo attribute (mimics v7).
    class _OldAgent:
        pass

    client.agent = _OldAgent()
    out = await client.host_info()
    assert out["ok"] is False
    assert "agent < v8" in out["error"]


async def test_self_update_threads_fields() -> None:
    """self_update must put service/exe/staged/sha/port on the wire."""
    from suspex.generated import suspex_pb2 as pb

    client = _make_client(2)
    captured: dict = {}

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        captured["req"] = req
        return pb.OpStatus(ok=True)

    client._call = fake_call  # type: ignore[method-assign]
    client.agent = type("_AgentStub", (), {"SelfUpdate": object()})()

    out = await client.self_update(
        "SuspexUmagent", r"C:\suspex\suspex_umagent.exe",
        r"C:\suspex\suspex_umagent.new", sha256="deadbeef", listen_port="50075")
    assert out["ok"] is True
    assert captured["req"].service_name == "SuspexUmagent"
    assert captured["req"].staged_path.endswith("umagent.new")
    assert captured["req"].sha256 == "deadbeef"
    assert captured["req"].listen_port == "50075"


async def test_host_info_envelope_shape() -> None:
    """host_info() should return the grouped envelope
    (identity/os/security/hardware/uptime/probe_errors), and each security
    posture bit should carry {value, source}. We monkey-patch _call to
    return a synthetic HostInfoResponse-shaped object."""
    from suspex.generated import suspex_pb2 as pb

    if not hasattr(pb, "HostInfoResponse"):
        import pytest
        pytest.skip("HostInfoResponse not present — regenerate Python stubs "
                    "with scripts/gen_proto.ps1")

    client = _make_client(2)
    resp = pb.HostInfoResponse()
    resp.status.ok = True
    resp.computer_name = "LAB-VM-01"
    resp.dns_hostname = "LAB-VM-01.example"
    resp.domain = "WORKGROUP"
    resp.logged_on_user = "analyst"
    resp.agent_run_as = "SYSTEM"
    resp.is_elevated = True
    resp.product_name = "Windows 11 Pro"
    resp.edition_id = "Professional"
    resp.display_version = "25H2"
    resp.release_id = "2609"
    resp.build_major = 26200
    resp.build_ubr = 9186
    resp.full_build_string = "26200.9186"
    resp.testsigning = True
    resp.testsigning_source = "driver"
    resp.hvci = False
    resp.hvci_source = "driver"
    resp.secureboot = False
    resp.secureboot_source = "api"
    resp.kernel_debugger = False
    resp.kernel_debugger_source = "api"
    resp.vbs_enabled = True
    resp.vbs_source = "registry"
    resp.driver_blocklist_on = True
    resp.driver_blocklist_source = "registry"
    resp.smep = True
    resp.smap = True
    resp.cpu_brand = "Fake CPU"
    resp.cpu_cores = 4
    resp.cpu_logical = 8
    resp.phys_mem_bytes = 8 * 1024 * 1024 * 1024
    resp.hypervisor_vendor = "Microsoft Hv"
    resp.is_vm = True
    resp.pc_uptime_ms = 3600 * 1000
    resp.agent_uptime_ms = 5 * 60 * 1000
    resp.service_uptime_ms = 6 * 60 * 1000
    resp.probe_errors.append("security_products: WSC enumeration is a follow-up slice")

    async def fake_call(rpc, req, timeout=None):  # noqa: ARG001
        assert isinstance(req, pb.HostInfoRequest)
        return resp

    client._call = fake_call  # type: ignore[method-assign]
    # Stand in an agent stub that HAS HostInfo so the version guard passes.
    client.agent = type("_AgentStub", (), {"HostInfo": object()})()

    out = await client.host_info(include_hardware=True)
    assert out["ok"] is True
    assert out["identity"]["computer_name"] == "LAB-VM-01"
    assert out["identity"]["is_elevated"] is True
    assert out["os"]["full_build_string"] == "26200.9186"
    assert out["os"]["display_version"] == "25H2"
    # Every security posture bit is a {value, source} dict at this layer;
    # the MCP action does the confidence-envelope wrap.
    assert out["security"]["testsigning"] == {"value": True, "source": "driver"}
    assert out["security"]["hvci"] == {"value": False, "source": "driver"}
    assert out["security"]["secureboot"] == {"value": False, "source": "api"}
    assert out["security"]["driver_blocklist_on"] == {
        "value": True, "source": "registry"}
    assert out["security"]["smep"] is True
    assert out["hardware"]["hypervisor_vendor"] == "Microsoft Hv"
    assert out["hardware"]["is_vm"] is True
    assert out["uptime"]["pc_uptime_ms"] == 3600 * 1000
    assert out["uptime"]["agent_uptime_ms"] == 5 * 60 * 1000
    assert out["uptime"]["service_uptime_ms"] == 6 * 60 * 1000
    assert any("WSC" in e for e in out["probe_errors"])
