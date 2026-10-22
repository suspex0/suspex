"""Tests for Unicorn-backed gadget / chain validation (analysis/rop_emu.py)
and its bin_manage surface (`gadget_check` / `chain_check`).

Skips when capstone or unicorn is missing (codegen extra).
"""
from __future__ import annotations

import pytest

import _pefixture as fx
from suspex.analysis import pe

pytest.importorskip("capstone")
pytest.importorskip("unicorn")

from suspex.analysis import engine, rop_emu  # noqa: E402

G = fx.IMAGE_BASE + fx.TEXT_RVA

CODE = (
    b"\x58\xC3"                       # 0x00 pop rax; ret
    b"\x5B\xC3"                       # 0x02 pop rbx; ret
    b"\x5F\x5E\xC3"                   # 0x04 pop rdi; pop rsi; ret
    b"\x48\x89\xC4\xC3"               # 0x07 mov rsp, rax; ret
    b"\x48\x8B\x03\xC3"               # 0x0B mov rax, [rbx]; ret
    b"\xFF\xE0"                       # 0x0F jmp rax
    b"\xCC"                           # 0x11 int3
    b"\xEB\xFE"                       # 0x12 jmp $ (infinite loop)
    + b"\x90" * (0x200 - 0x14)
)


def _view():
    data = fx.build_pe(code=CODE)
    img = pe.parse(data, layout="file")
    return engine.ImageView(img)


# ------------------------------------------------------- module-level ----

class TestValidateGadget:
    def test_pop_ret_returns(self) -> None:
        out = rop_emu.validate_gadget(_view(), G + 0x00)
        assert out["verdict"] == "returns"
        assert out["disasm"] == ["pop rax", "ret"]
        # pop took the sentinel fill value, ret consumed the next slot.
        assert out["regs_changed"]["rax"] == rop_emu.SENTINEL_VA
        assert out["rsp_delta"] == 16
        assert out["unmapped"] == []

    def test_multi_pop(self) -> None:
        out = rop_emu.validate_gadget(_view(), G + 0x04)
        assert out["verdict"] == "returns"
        assert out["regs_changed"]["rdi"] == rop_emu.SENTINEL_VA
        assert out["regs_changed"]["rsi"] == rop_emu.SENTINEL_VA
        assert out["rsp_delta"] == 24

    def test_stack_pivot_lands_on_ret_sled(self) -> None:
        # rax is seeded into the scratch region, which is filled with
        # sentinel qwords — the pivot + ret chain completes.
        out = rop_emu.validate_gadget(_view(), G + 0x07)
        assert out["verdict"] == "returns"
        assert "stack_pivot" in _cats(G + 0x07)
        assert out["rsp_delta"] != 8  # rsp was re-pointed, not popped

    def test_mem_load_reads_scratch(self) -> None:
        out = rop_emu.validate_gadget(_view(), G + 0x0B)
        assert out["verdict"] == "returns"
        assert out["regs_changed"]["rax"] == rop_emu.SENTINEL_VA

    def test_jmp_into_non_exec_faults(self) -> None:
        # rax seeds into scratch (rw, not exec) → fetch fault, classified.
        out = rop_emu.validate_gadget(_view(), G + 0x0F)
        assert out["verdict"] == "fault:fetch"
        assert out["unmapped"][0]["access"] == "fetch"

    def test_infinite_loop_caps(self) -> None:
        out = rop_emu.validate_gadget(_view(), G + 0x12, max_ins=50)
        assert out["verdict"] == "cap"
        assert out["insns_executed"] >= 50

    def test_non_exec_target_refused(self) -> None:
        with pytest.raises(ValueError):
            rop_emu.validate_gadget(_view(), fx.IMAGE_BASE + 0x2500)

    def test_stack_qwords_seed(self) -> None:
        out = rop_emu.validate_gadget(_view(), G + 0x00,
                                      stack_qwords=[0xDEAD])
        assert out["verdict"] == "returns"
        assert out["regs_changed"]["rax"] == 0xDEAD


class TestValidateChain:
    def test_happy_path(self) -> None:
        chain = [G + 0x00, 0x4141, G + 0x02, 0x4242, G + 0x00, 0x4343]
        out = rop_emu.validate_chain(_view(), chain)
        assert out["verdict"] == "completed"
        assert out["final_regs"]["rax"] == 0x4343
        assert out["final_regs"]["rbx"] == 0x4242
        assert out["consumed"] == 6
        assert [t["va"] for t in out["trace"]] == [G, G + 0x02, G]

    def test_expected_match(self) -> None:
        chain = [G + 0x00, 0x4141]
        out = rop_emu.validate_chain(
            _view(), chain,
            expected={"regs": {"rax": 0x4141}, "rsp_delta": 16})
        assert out["verdict"] == "completed"
        assert "expected_mismatch" not in out

    def test_expected_mismatch(self) -> None:
        chain = [G + 0x00, 0x4141]
        out = rop_emu.validate_chain(
            _view(), chain,
            expected={"regs": {"rax": 0xDEAD}, "rsp_delta": 8})
        kinds = {m.get("reg") or m.get("field")
                 for m in out["expected_mismatch"]}
        assert kinds == {"rax", "rsp_delta"}

    def test_broken_chain_faults(self) -> None:
        # jmp rax with the scratch seed → fetch fault right after entry.
        # chain[0] itself counts as consumed (rip starts there).
        out = rop_emu.validate_chain(_view(), [G + 0x0F])
        assert out["verdict"] == "fault:fetch"
        assert out["consumed"] == 1

    def test_unmapped_entry_warned(self) -> None:
        out = rop_emu.validate_chain(_view(), [0xDEADBEEF, 0x1])
        assert out["verdict"].startswith("fault")
        assert out["non_exec_entries"][0]["index"] == 0
        assert any("unmapped" in w for w in out["warnings"])

    def test_empty_chain_refused(self) -> None:
        with pytest.raises(ValueError):
            rop_emu.validate_chain(_view(), [])

    def test_pivot_chain_still_completes(self) -> None:
        # mov rsp, rax; ret — rax seeds into the sentinel-filled scratch.
        out = rop_emu.validate_chain(_view(), [G + 0x07])
        assert out["verdict"] == "completed"


def _cats(va: int) -> set:
    idx = __import__("suspex.analysis.rop", fromlist=["rop"]).build_index(
        _view())
    for g in idx.gadgets:
        if g.va == va:
            return set(g.categories)
    return set()


# ---------------------------------------------------------- kernel range ----

def _kernel_view(base: int):
    """As-mapped buffer (the `source='memory'` shape) viewed at a kernel
    VA — unicorn only *executes* <= 52-bit VAs, so this is the regression
    case for the relocation in `_prepare_engine`."""
    file_bytes = fx.build_pe(code=CODE)
    fimg = pe.parse(file_bytes, layout="file")
    buf = bytearray(max(fimg.size_of_image, len(file_bytes)))
    buf[:0x200] = file_bytes[:0x200]
    for s in fimg.sections:
        buf[s.va:s.va + s.raw_size] = \
            file_bytes[s.raw_off:s.raw_off + s.raw_size]
    img = pe.parse(bytes(buf), layout="image")
    return engine.ImageView(img, base_va=base)


KBASE = 0xFFFFF805_46CF0000
KG = KBASE + fx.TEXT_RVA


class TestKernelRange:
    def test_gadget_at_kernel_va(self) -> None:
        out = rop_emu.validate_gadget(_kernel_view(KBASE), KG + 0x00)
        assert out["verdict"] == "returns"
        assert out["rsp_delta"] == 16
        assert out["regs_changed"]["rax"] == rop_emu.SENTINEL_VA

    def test_chain_at_kernel_va(self) -> None:
        chain = [KG + 0x00, 0x4141, KG + 0x02, 0x4242]
        out = rop_emu.validate_chain(_kernel_view(KBASE), chain)
        assert out["verdict"] == "completed"
        assert out["final_regs"]["rax"] == 0x4141
        assert out["final_regs"]["rbx"] == 0x4242
        assert out["consumed"] == 4
        assert [t["va"] for t in out["trace"]] == [KG, KG + 0x02]

    def test_kernel_fault_reports_full_va(self) -> None:
        # Unmapped chain entry in kernel space → the reported fault VA is
        # un-masked back to its full 64-bit form.
        bogus = 0xFFFFF805_DEAD0000
        out = rop_emu.validate_chain(_kernel_view(KBASE), [bogus])
        assert out["verdict"] == "fault:fetch"
        assert out["unmapped"][0]["va"] == bogus


# --------------------------------------------------------- tool level ----

import asyncio  # noqa: E402
from suspex.caller import CLIENT_ID  # noqa: E402
from suspex.clients import ClientRegistry  # noqa: E402
from suspex.config import SuspexConfig, TargetConfig  # noqa: E402
from suspex.findings import FindingsLedger  # noqa: E402
from suspex.ida_bridge import IdaBridge, IdaConfigLite  # noqa: E402
from suspex.leases import LeaseManager  # noqa: E402
from suspex.mcp.tools import Context, build_server  # noqa: E402
from suspex.ownership import OwnershipRegistry  # noqa: E402
from suspex.session import Session  # noqa: E402


async def _ctx(tmp_path):
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    art_dir = tmp_path / "artifacts"
    (art_dir / "spill").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(art_dir / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), art_dir)
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=ClientRegistry(),
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          ClientRegistry().publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-test")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        import json as _json
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return {"raw": body}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    err = body.get("error")
    if isinstance(err, dict):
        merged.update(err)
    merged.setdefault("ok", body.get("ok"))
    if isinstance(body.get("summary"), dict):
        merged.setdefault("summary", body["summary"])
    return merged


def _seed(tmp_path) -> None:
    (tmp_path / "artifacts" / "g.sys").write_bytes(fx.build_pe(code=CODE))


async def test_gadget_check_action(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(tmp_path)
    body = await _call(server, "bin_manage",
                       {"action": "gadget_check", "path": "g.sys",
                        "target": hex(G + 0x00)})
    assert body["ok"] is True
    assert body["verdict"] == "returns"
    assert body["rsp_delta"] == 16

    body = await _call(server, "bin_manage",
                       {"action": "gadget_check", "path": "g.sys",
                        "target": hex(fx.IMAGE_BASE + 0x2500)})
    assert body["ok"] is False and body["kind"] == "bad_arg"

    body = await _call(server, "bin_manage",
                       {"action": "gadget_check", "path": "g.sys"})
    assert body["ok"] is False and body["kind"] == "bad_arg"


async def test_chain_check_action(tmp_path) -> None:
    ctx, server = await _ctx(tmp_path)
    _seed(tmp_path)
    chain_json = ('[%s, "0x4141", %s, "0x4242", %s, "0x4343"]'
                  % (hex(G), hex(G + 0x02), hex(G)))
    body = await _call(server, "bin_manage",
                       {"action": "chain_check", "path": "g.sys",
                        "chain": chain_json})
    assert body["ok"] is True
    assert body["verdict"] == "completed"
    assert body["consumed"] == 6
    assert body["trace"]

    # csv form + expected match
    body = await _call(server, "bin_manage",
                       {"action": "chain_check", "path": "g.sys",
                        "chain": f"{hex(G)},0x4141",
                        "expected_json": '{"regs": {"rax": "0x4141"}}'})
    assert body["ok"] is True
    assert body["verdict"] == "completed"
    assert "expected_mismatch" not in body

    # malformed chain / expected
    body = await _call(server, "bin_manage",
                       {"action": "chain_check", "path": "g.sys",
                        "chain": "nope"})
    assert body["ok"] is False and body["kind"] == "bad_arg"
    body = await _call(server, "bin_manage",
                       {"action": "chain_check", "path": "g.sys",
                        "chain": hex(G),
                        "expected_json": "{bad json"})
    assert body["ok"] is False and body["kind"] == "bad_arg"
