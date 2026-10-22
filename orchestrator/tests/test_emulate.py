"""End-to-end tests for the emulator surface (`emulate_manage`).

These target the **unicorn** engine — bare CPU, no OS surface — because
it's the reliable path in every environment where the codegen extra
installs. Speakeasy-specific behavior (API hooks, PE loader) is
exercised in `test_emulate_speakeasy.py`, which skips if speakeasy
isn't importable.
"""
from __future__ import annotations

import pytest

from suspex import codegen as cg
from suspex import emulate as em


pytestmark = pytest.mark.skipif(
    not cg.unicorn_available(),
    reason="unicorn not installed (pip install suspex0[codegen])",
)


@pytest.fixture(autouse=True)
def _reset_registry():
    em.EMU_SESSIONS.clear()
    yield
    for sid in list(em.EMU_SESSIONS):
        em.close_session(sid)


class TestSessionLifecycle:
    def test_create_and_list(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        assert s.id.startswith("e")
        rows = em.list_sessions()
        assert any(r["session_id"] == s.id for r in rows)

    def test_bad_arch(self) -> None:
        with pytest.raises(ValueError):
            em.create_session(arch="arm64", engine="unicorn")

    def test_close(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        assert em.close_session(s.id)
        assert s.id not in em.EMU_SESSIONS

    def test_unknown_engine(self) -> None:
        with pytest.raises(ValueError):
            em.create_session(arch="x64", engine="wat")


class TestShellcodeRoundtrip:
    def test_mov_rax_1_ret(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        # mov rax, 1; ret
        payload, _, _ = cg.assemble("mov rax, 1; ret", "x64")
        s.engine.load_shellcode(payload, 0)
        s.engine.run(max_ins=10)
        regs = s.engine.read_regs()
        assert regs["rax"] == 1

    def test_addition(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        payload, _, _ = cg.assemble(
            "mov rax, 0x10; mov rbx, 0x20; add rax, rbx; ret", "x64")
        s.engine.load_shellcode(payload, 0)
        s.engine.run(max_ins=100)
        assert s.engine.read_regs()["rax"] == 0x30

    def test_x86_shellcode(self) -> None:
        s = em.create_session(arch="x86", engine="unicorn")
        payload, _, _ = cg.assemble("mov eax, 0x1234; ret", "x86")
        s.engine.load_shellcode(payload, 0)
        s.engine.run(max_ins=10)
        assert s.engine.read_regs()["eax"] == 0x1234


class TestMemMap:
    def test_map_read_write(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        s.engine.mem_map(0x2000, 0x1000, "rwx", "scratch")
        s.engine.mem_write(0x2000, b"\xaa\xbb\xcc\xdd")
        assert s.engine.mem_read(0x2000, 4) == b"\xaa\xbb\xcc\xdd"

    def test_xor_decoder(self) -> None:
        # A small xor decoder against a scratch page.
        s = em.create_session(arch="x64", engine="unicorn")
        code = (
            "mov rdi, 0x2000\n"
            "mov rcx, 8\n"
            "loop_start:\n"
            "xor byte ptr [rdi], 0xAA\n"
            "inc rdi\n"
            "dec rcx\n"
            "jnz loop_start\n"
            "ret\n"
        )
        payload, _, _ = cg.assemble(code, "x64")
        s.engine.load_shellcode(payload, 0)
        s.engine.mem_map(0x2000, 0x1000, "rwx", "scratch")
        # 8 bytes of "\xEA...\xEA" XOR 0xAA = "\x40...\x40" ('@')
        s.engine.mem_write(0x2000, b"\xEA" * 8)
        s.engine.run(max_ins=1000)
        assert s.engine.mem_read(0x2000, 8) == b"@" * 8


class TestRegsWrite:
    def test_set_and_read(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        s.engine.write_regs({"rax": 0x1234, "rcx": "0xABCD"})
        r = s.engine.read_regs()
        assert r["rax"] == 0x1234
        assert r["rcx"] == 0xABCD

    def test_bad_reg_name(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        with pytest.raises(ValueError):
            s.engine.write_regs({"nonsense": 1})


class TestSnapshots:
    def test_snapshot_restore_roundtrip(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        payload, _, _ = cg.assemble("mov rax, 1; ret", "x64")
        s.engine.load_shellcode(payload, 0)
        s.engine.mem_map(0x3000, 0x1000, "rwx", "state")
        s.engine.mem_write(0x3000, b"BEFORE" + b"\x00" * 10)
        snap = s.engine.snapshot()

        # Mutate state.
        s.engine.mem_write(0x3000, b"AFTER!" + b"\x00" * 10)
        s.engine.write_regs({"rax": 0xDEADBEEF})
        assert s.engine.mem_read(0x3000, 6) == b"AFTER!"
        assert s.engine.read_regs()["rax"] == 0xDEADBEEF

        # Restore.
        s.engine.restore(snap)
        assert s.engine.mem_read(0x3000, 6) == b"BEFORE"
        assert s.engine.read_regs()["rax"] != 0xDEADBEEF


class TestHooks:
    def test_addr_hook_fires(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        # mov rax, 1; nop; nop; ret at 0x140001000
        payload, _, _ = cg.assemble("mov rax, 1; nop; nop; ret", "x64")
        entry = s.engine.load_shellcode(payload, 0)
        # Hook on the first nop (7 bytes into the buffer).
        hid = s.engine.add_hook({"kind": "addr",
                                  "address": entry + 7,
                                  "action": "log"})
        s.engine.run(max_ins=10)
        assert any(e.get("kind") == "addr_hook" and e.get("address") == entry + 7
                   for e in s.engine._events)
        assert s.engine.remove_hook(hid)

    def test_unicorn_rejects_api_hook(self) -> None:
        s = em.create_session(arch="x64", engine="unicorn")
        with pytest.raises(ValueError):
            s.engine.add_hook({"kind": "api", "api": "kernel32!Foo"})


class TestEventRing:
    def test_ring_wraps(self) -> None:
        # Push more entries than the ring holds; oldest should drop.
        s = em.create_session(arch="x64", engine="unicorn")
        ring = s.engine._events
        cap = ring.maxlen
        for i in range(cap + 100):
            ring.append({"i": i})
        assert len(ring) == cap
        # First entry survived should be at index 100 (the earliest 100 dropped).
        assert ring[0]["i"] == 100
