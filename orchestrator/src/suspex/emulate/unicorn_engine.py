"""Bare Unicorn backend — raw CPU, no Windows API veneer."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from ..codegen import CodegenUnavailable, _load_unicorn
from .base import EVENT_RING_DEFAULT, _Engine


# --- Unicorn backend (raw CPU) --------------------------------------------


class _UnicornEngine(_Engine):
    """Bare Unicorn engine — no OS emulation. Enough for shellcode that
    doesn't touch the Windows API.
    """

    kind = "unicorn"
    # Base VA for the shellcode region and initial stack. Kept low enough
    # to interoperate with typical x86 tests and high enough on x64 to
    # look "userlandy".
    _SHELLCODE_BASE_X64 = 0x140001000
    _SHELLCODE_BASE_X86 = 0x00401000
    _STACK_TOP_X64 = 0x00007FFF_00000000
    _STACK_TOP_X86 = 0x7FFF_0000
    _STACK_SIZE = 0x10000

    def __init__(self, arch: str) -> None:
        uc = _load_unicorn()
        self._uc_mod = uc
        self.arch = arch
        if arch == "x64":
            mode = uc.UC_MODE_64
        elif arch == "x86":
            mode = uc.UC_MODE_32
        else:
            raise ValueError(f"unicorn engine: unsupported arch {arch!r}")
        self._mode = mode
        self._eng = uc.Uc(uc.UC_ARCH_X86, mode)
        self._maps: list[tuple[int, int, str]] = []  # (base, size, label)
        self._hooks: dict[str, tuple[str, Any]] = {}
        self._hook_seq = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=EVENT_RING_DEFAULT)
        # Pre-map a stack region so shellcode has somewhere to push.
        stack_top = (self._STACK_TOP_X64 if arch == "x64"
                      else self._STACK_TOP_X86)
        stack_base = stack_top - self._STACK_SIZE
        self._eng.mem_map(stack_base, self._STACK_SIZE, uc.UC_PROT_ALL)
        self._maps.append((stack_base, self._STACK_SIZE, "stack"))
        # RSP/ESP starts near the top of the stack.
        sp_reg = self._sp_reg()
        self._eng.reg_write(sp_reg, stack_top - 0x100)

    # --- register helpers -------------------------------------------------

    def _sp_reg(self) -> int:
        uc = self._uc_mod
        # x86.UC_X86_REG_RSP / UC_X86_REG_ESP live under uc.x86_const.
        return uc.x86_const.UC_X86_REG_RSP if self.arch == "x64" \
               else uc.x86_const.UC_X86_REG_ESP

    def _ip_reg(self) -> int:
        uc = self._uc_mod
        return uc.x86_const.UC_X86_REG_RIP if self.arch == "x64" \
               else uc.x86_const.UC_X86_REG_EIP

    _X64_REGS = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "rflags",
    ]
    _X86_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp",
                  "ebp", "eip", "eflags"]

    def _reg_id(self, name: str) -> int:
        uc = self._uc_mod
        key = f"UC_X86_REG_{name.upper()}"
        val = getattr(uc.x86_const, key, None)
        if val is None:
            raise ValueError(f"unknown register {name!r}")
        return val

    # --- shellcode loading ------------------------------------------------

    def load_shellcode(self, data: bytes, entry: int) -> int:
        uc = self._uc_mod
        if not entry:
            entry = (self._SHELLCODE_BASE_X64 if self.arch == "x64"
                      else self._SHELLCODE_BASE_X86)
        # Round up to page and ensure headroom past the last byte.
        size = max(len(data), 0x1000)
        size = (size + 0xFFF) & ~0xFFF
        # Guard against a re-load overlapping an existing map.
        for base, sz, _ in self._maps:
            if base <= entry < base + sz:
                # Already mapped — just write into it.
                self._eng.mem_write(entry, data)
                self.entry = entry
                return entry
        self._eng.mem_map(entry, size, uc.UC_PROT_ALL)
        self._maps.append((entry, size, "shellcode"))
        self._eng.mem_write(entry, data)
        # Set IP to entry so `run()`/`step()` start here without an
        # explicit `until` argument.
        self._eng.reg_write(self._ip_reg(), entry)
        self.entry = entry
        return entry

    def load_pe(self, path: str, cmdline: str = "",
                image_base: int = 0) -> int:
        raise CodegenUnavailable("unicorn engine: load_pe requires "
                                  "the speakeasy backend (image loader "
                                  "+ import stubs)")

    # --- execution --------------------------------------------------------

    def run(self, *, until: int = 0, max_ins: int = 0,
            timeout_s: float = 0.0) -> dict[str, Any]:
        uc = self._uc_mod
        ip = self._eng.reg_read(self._ip_reg())
        begin = ip
        end = until or (begin + 0x10000)
        started = time.time()
        halt_reason = "ok"
        try:
            self._eng.emu_start(begin, end,
                                 timeout=int(timeout_s * 1_000_000) if timeout_s else 0,
                                 count=int(max_ins) if max_ins else 0)
        except Exception as exc:
            halt_reason = f"{type(exc).__name__}: {exc}"
            self._events.append({"kind": "exception",
                                  "ip": self._eng.reg_read(self._ip_reg()),
                                  "reason": halt_reason,
                                  "ts": time.time()})
        duration = time.time() - started
        cur_ip = self._eng.reg_read(self._ip_reg())
        return {"halt_reason": halt_reason,
                "start_ip": begin,
                "end_ip": cur_ip,
                "duration_s": round(duration, 6),
                "api_calls": [],
                "events": list(self._events)}

    def step(self, n: int = 1) -> dict[str, Any]:
        return self.run(max_ins=int(n or 1))

    # --- regs -------------------------------------------------------------

    def read_regs(self) -> dict[str, int]:
        names = self._X64_REGS if self.arch == "x64" else self._X86_REGS
        out: dict[str, int] = {}
        for r in names:
            try:
                out[r] = int(self._eng.reg_read(self._reg_id(r)))
            except Exception:  # pragma: no cover
                pass
        return out

    def write_regs(self, regs: dict[str, int]) -> None:
        for k, v in regs.items():
            try:
                iv = int(v, 0) if isinstance(v, str) else int(v)
            except Exception as exc:
                raise ValueError(f"regs: {k}={v!r} not a valid int/hex") from exc
            self._eng.reg_write(self._reg_id(k), iv)

    # --- memory -----------------------------------------------------------

    def mem_map(self, address: int, size: int, prot: str = "rwx",
                label: str = "") -> None:
        uc = self._uc_mod
        p = 0
        if "r" in prot: p |= uc.UC_PROT_READ
        if "w" in prot: p |= uc.UC_PROT_WRITE
        if "x" in prot: p |= uc.UC_PROT_EXEC
        if p == 0:
            p = uc.UC_PROT_ALL
        # Round size up to page.
        size = (size + 0xFFF) & ~0xFFF
        self._eng.mem_map(address, size, p)
        self._maps.append((address, size, label or "user"))

    def mem_unmap(self, address: int, size: int) -> None:
        size = (size + 0xFFF) & ~0xFFF
        self._eng.mem_unmap(address, size)
        self._maps = [m for m in self._maps if not (m[0] == address and m[1] == size)]

    def mem_read(self, address: int, size: int) -> bytes:
        return bytes(self._eng.mem_read(address, size))

    def mem_write(self, address: int, data: bytes) -> int:
        self._eng.mem_write(address, bytes(data))
        return len(data)

    # --- hooks ------------------------------------------------------------

    def add_hook(self, spec: dict[str, Any]) -> str:
        # Unicorn engine only supports address hooks (no API surface).
        uc = self._uc_mod
        kind = spec.get("kind", "addr")
        if kind != "addr":
            raise ValueError(f"unicorn engine: hook kind={kind!r} not "
                              "supported (use engine=speakeasy for API hooks)")
        addr = int(spec.get("address", 0), 0) if isinstance(spec.get("address"), str) \
                else int(spec.get("address", 0))
        action = spec.get("action", "log")
        events = self._events

        def _cb(mu, address, size, _user):
            events.append({"kind": "addr_hook",
                            "address": address,
                            "size": size,
                            "ts": time.time()})
            if action == "skip":
                mu.reg_write(self._ip_reg(), address + size)
            elif action == "return":
                # Naive ret emulation: pop and jump.
                sp = mu.reg_read(self._sp_reg())
                ret_addr = int.from_bytes(mu.mem_read(sp, 8 if self.arch == "x64" else 4),
                                          "little")
                mu.reg_write(self._sp_reg(),
                             sp + (8 if self.arch == "x64" else 4))
                mu.reg_write(self._ip_reg(), ret_addr)

        h = self._eng.hook_add(uc.UC_HOOK_CODE, _cb, begin=addr, end=addr)
        self._hook_seq += 1
        hid = f"h{self._hook_seq:04d}"
        self._hooks[hid] = ("addr", h)
        return hid

    def remove_hook(self, hook_id: str) -> bool:
        entry = self._hooks.pop(hook_id, None)
        if entry is None:
            return False
        _, h = entry
        try:
            self._eng.hook_del(h)
        except Exception:  # pragma: no cover
            pass
        return True

    def uc_hook(self, hook_type: int, callback: Any) -> Any:
        """Register a raw Uc hook and return the engine handle.

        For analysis passes that need coverage the session-level hook
        registry doesn't model (``UC_HOOK_MEM_WRITE`` /
        ``UC_HOOK_MEM_UNMAPPED`` — see ``analysis/rop_emu.py``). Delete
        with :meth:`uc_hook_del`.
        """
        return self._eng.hook_add(hook_type, callback)

    def uc_hook_del(self, handle: Any) -> None:
        try:
            self._eng.hook_del(handle)
        except Exception:  # pragma: no cover
            pass

    # --- snapshots --------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        # Capture regs + every mapped region's contents.
        blobs = []
        for base, size, label in self._maps:
            blobs.append({"base": base, "size": size, "label": label,
                          "data": bytes(self._eng.mem_read(base, size))})
        return {"regs": self.read_regs(), "blobs": blobs,
                "arch": self.arch, "entry": self.entry}

    def restore(self, snap: dict[str, Any]) -> None:
        for b in snap.get("blobs", []):
            base, size = int(b["base"]), int(b["size"])
            # Ensure region exists.
            if not any(m[0] <= base < m[0] + m[1] for m in self._maps):
                self.mem_map(base, size, "rwx", b.get("label", ""))
            self._eng.mem_write(base, bytes(b["data"]))
        self.write_regs(snap.get("regs", {}))
        self.entry = int(snap.get("entry", 0))

    def close(self) -> None:
        # Unicorn instances free on GC; drop the handle explicitly.
        self._eng = None
