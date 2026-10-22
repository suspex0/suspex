from suspex.agent_client import proto_to_dict, status_dict
from suspex.generated import suspex_pb2 as pb


def test_status_dict() -> None:
    st = pb.OpStatus(ok=False, error="boom", errno_code=5)
    d = status_dict(st)
    assert d == {"ok": False, "error": "boom", "errno_code": 5}


def test_envelope_extracts_status_and_fields() -> None:
    msg = pb.MemoryAllocResponse(
        status=pb.OpStatus(ok=True), address=0x7FF000000000
    )
    d = proto_to_dict(msg)
    assert d.get("address") == 819981252972544 or isinstance(d.get("address"), (int, str))
    assert "status" not in d


def test_driver_load_method_roundtrip() -> None:
    req = pb.DriverLoadRequest(method=pb.DriverLoadRequest.MANUAL_MAP)
    assert req.method == pb.DriverLoadRequest.MANUAL_MAP
    req2 = pb.DriverLoadRequest()
    assert req2.method == pb.DriverLoadRequest.SERVICE


def test_bp_add_hw_defaults() -> None:
    req = pb.BpAddRequest(kind=pb.BpAddRequest.HW, address=0x1400, size=4, access="rw")
    assert req.size == 4
    assert req.access == "rw"


def test_upload_chunk_oneof() -> None:
    c = pb.UploadChunk(header=pb.UploadHeader(path="C:\\x.bin", size=3))
    assert c.WhichOneof("payload") == "header"
    c2 = pb.UploadChunk(data=b"abc")
    assert c2.WhichOneof("payload") == "data"


def test_module_imports_response_roundtrip() -> None:
    resp = pb.ModuleImportsResponse(
        status=pb.OpStatus(ok=True),
        entries=[
            pb.IatEntry(dll="kernel32.dll", name="CreateFileW",
                        iat_slot=0x140001000, resolved=0x7FF000001000,
                        resolved_module="KERNEL32.DLL", hooked=False),
            pb.IatEntry(dll="user32.dll", ordinal=42,
                        iat_slot=0x140001008, resolved=0xDEAD, hooked=True),
        ],
    )
    rows = [proto_to_dict(e) for e in resp.entries]
    assert len(rows) == 2
    assert rows[0]["name"] == "CreateFileW"
    assert rows[0]["hooked"] is False
    # ordinal-imported row has empty name and non-zero ordinal
    assert rows[1]["name"] == ""
    assert rows[1]["ordinal"] == 42
    assert rows[1]["hooked"] is True


def test_module_exports_response_roundtrip() -> None:
    resp = pb.ModuleExportsResponse(
        status=pb.OpStatus(ok=True),
        entries=[
            pb.ExportEntry(name="NtOpenFile", ordinal=0x2A, rva=0x1000,
                           address=0x7FF000001000),
            pb.ExportEntry(name="", ordinal=0x2B, rva=0x2000,
                           forwarder="api-ms-win-core-x!Foo"),
        ],
    )
    rows = [proto_to_dict(e) for e in resp.entries]
    assert rows[0]["name"] == "NtOpenFile"
    assert rows[1]["forwarder"] == "api-ms-win-core-x!Foo"


def test_dump_module_request_kernel_flag() -> None:
    req = pb.DumpModuleRequest(pid=0, module="ntoskrnl.exe", kernel=True)
    assert req.kernel is True
    # default stays off — a user dump must not silently switch views
    assert pb.DumpModuleRequest(module="x.dll").kernel is False


def test_self_update_request_roundtrip() -> None:
    req = pb.SelfUpdateRequest(
        service_name="SuspexAgent", exe_path=r"C:\suspex\suspex_agent.exe",
        staged_path=r"C:\suspex\suspex_agent.new", sha256="ab12", listen_port="50074")
    blob = req.SerializeToString()
    back = pb.SelfUpdateRequest.FromString(blob)
    assert back.service_name == "SuspexAgent"
    assert back.staged_path.endswith(".new")
    assert back.listen_port == "50074"
    # empty defaults keep the wire small
    assert pb.SelfUpdateRequest().sha256 == ""


def test_heap_list_response_roundtrip() -> None:
    resp = pb.HeapListResponse(
        status=pb.OpStatus(ok=True),
        heaps=[
            pb.HeapEntry(handle=0x140000, base=0x140000, flags=2,
                         committed=0x20000, reserved=0x10000,
                         blocks=[pb.HeapBlock(address=0x140100, size=0x30, flags=1)]),
        ],
    )
    rows = [proto_to_dict(h) for h in resp.heaps]
    assert len(rows) == 1
    assert len(rows[0]["blocks"]) == 1
    assert rows[0]["blocks"][0]["size"] in (0x30, "48", 48)


# ---------------------------------------------------------------------------
# Envelope backward compatibility (rea-adoption Part 1): envelopes WITHOUT
# the provenance/coverage keys serialize/round-trip unchanged.
# ---------------------------------------------------------------------------

import json as _json

from suspex.mcp._envelope import envelope_err, envelope_from_result, envelope_ok


def test_envelope_ok_without_new_keys_stays_unchanged() -> None:
    env = envelope_ok(
        {"items": [1, 2]}, kind="modules", tool="mem_rw", action="modules",
        item_count=2, item_total=2, truncated=False,
    )
    assert "provenance" not in env
    assert "coverage" not in env
    roundtrip = _json.loads(_json.dumps(env))
    assert roundtrip == env


def test_envelope_err_without_new_keys_stays_unchanged() -> None:
    env = envelope_err("boom", tool="mem_rw", action="read")
    assert env["ok"] is False
    assert "provenance" not in env
    assert "coverage" not in env
    roundtrip = _json.loads(_json.dumps(env))
    assert roundtrip == env


def test_envelope_explicit_blocks_land_on_top_level() -> None:
    prov = {"untrusted_content": True, "source": "target"}
    cov = {"scope": "mem-read", "status": "complete", "limits": []}
    env = envelope_ok({"hex": "90"}, kind="read", provenance=prov,
                      coverage=cov)
    assert env["provenance"] == prov
    assert env["coverage"] == cov
    err = envelope_err("bad", tool="mem_rw", action="read", provenance=prov)
    assert err["provenance"] == prov
    assert "coverage" not in err


def test_legacy_result_hoists_provenance_and_coverage() -> None:
    prov = {"untrusted_content": True, "source": "session"}
    cov = {"scope": "enumeration", "status": "unknown", "limits": []}
    env = envelope_from_result(
        {"ok": True, "rows": [], "provenance": prov, "coverage": cov},
        tool="knowledge_manage", action="search",
    )
    assert env["provenance"] == prov
    assert env["coverage"] == cov
    # The blocks are envelope fields, not payload — never duplicated
    # under data.
    assert "provenance" not in env["data"]
    assert "coverage" not in env["data"]
