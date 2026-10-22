"""Common bookkeeping for the emulator package: session registry, id
allocator, event-ring defaults, and the abstract ``_Engine`` contract
that Speakeasy / Unicorn backends implement.
"""

from __future__ import annotations

import atexit
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .session import EmuSession

# ---------------------------------------------------------------------------
# Session registry
# ---------------------------------------------------------------------------

EMU_SESSIONS: dict[str, "EmuSession"] = {}
_SESSION_SEQ = [0]


def _shutdown_sessions() -> None:
    # Free every engine while the interpreter (and the native unicorn /
    # speakeasy module state) is still healthy. If sessions survive to
    # module teardown, the native backends free in the wrong order and
    # Windows fatal exceptions (access violations) print at exit.
    for sid in list(EMU_SESSIONS):
        sess = EMU_SESSIONS.get(sid)
        if sess is None:
            continue
        try:
            sess.engine.close()
        except Exception:  # pragma: no cover - best-effort teardown
            pass
    EMU_SESSIONS.clear()


atexit.register(_shutdown_sessions)

# Default event ring size — same shape used by mem watch (bounded deque).
EVENT_RING_DEFAULT = 4096
# Idle-close TTL. The MCP layer runs a cleanup pass whenever `list` is
# called, so this is the wall-clock idle threshold after which a session
# is treated as abandoned.
SESSION_TTL_S = 1800.0


def _next_id() -> str:
    _SESSION_SEQ[0] += 1
    return f"e{_SESSION_SEQ[0]:04d}"


# ---------------------------------------------------------------------------
# Engine abstraction
# ---------------------------------------------------------------------------


class _Engine:
    """Common contract implemented by both Speakeasy and Unicorn backends.

    Only the operations the ``emulate_manage`` MCP surface reaches are
    exposed. Anything richer stays inside the concrete engine class.
    """

    arch: str = "x64"
    entry: int = 0
    kind: str = "abstract"

    def load_shellcode(self, data: bytes, entry: int) -> int: ...
    def load_pe(self, path: str, cmdline: str = "",
                image_base: int = 0) -> int: ...
    def run(self, *, until: int = 0, max_ins: int = 0,
            timeout_s: float = 0.0) -> dict[str, Any]: ...
    def step(self, n: int = 1) -> dict[str, Any]: ...
    def read_regs(self) -> dict[str, int]: ...
    def write_regs(self, regs: dict[str, int]) -> None: ...
    def mem_map(self, address: int, size: int, prot: str = "rwx",
                label: str = "") -> None: ...
    def mem_unmap(self, address: int, size: int) -> None: ...
    def mem_read(self, address: int, size: int) -> bytes: ...
    def mem_write(self, address: int, data: bytes) -> int: ...
    def add_hook(self, spec: dict[str, Any]) -> str: ...
    def remove_hook(self, hook_id: str) -> bool: ...
    def snapshot(self) -> dict[str, Any]: ...
    def restore(self, snap: dict[str, Any]) -> None: ...
    def close(self) -> None: ...
