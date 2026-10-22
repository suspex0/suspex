"""Public session type, session-registry helpers, and target-seeding."""

from __future__ import annotations

import time
from typing import Any

from ..codegen import CodegenUnavailable
from .base import EMU_SESSIONS, SESSION_TTL_S, _Engine, _next_id
from .speakeasy_engine import _SpeakeasyEngine
from .unicorn_engine import _UnicornEngine


# ---------------------------------------------------------------------------
# Public session type
# ---------------------------------------------------------------------------


class EmuSession:
    """One live emulator instance + its bookkeeping (event ring, hook
    registry, snapshot store). Callers should not construct these
    directly — use :func:`create_session`.
    """

    def __init__(self, session_id: str, *,
                 arch: str, mode: str, engine: _Engine,
                 flavor: str = "latest") -> None:
        self.id = session_id
        self.arch = arch
        self.mode = mode
        self.engine = engine
        self.flavor = flavor
        self.cursor: int = 0
        self.created_ts = time.time()
        self.last_ts = self.created_ts
        self.snapshots: dict[str, dict[str, Any]] = {}
        self._snap_seq = 0

    def touch(self) -> None:
        self.last_ts = time.time()

    def idle_s(self) -> float:
        return time.time() - self.last_ts

    def summary(self) -> dict[str, Any]:
        return {"session_id": self.id, "arch": self.arch, "mode": self.mode,
                "engine": self.engine.kind,
                "entry": hex(self.engine.entry) if self.engine.entry else "0x0",
                "cursor": hex(self.cursor),
                "created_ts": self.created_ts,
                "idle_s": round(self.idle_s(), 1),
                "snapshots": len(self.snapshots)}

    def add_snapshot(self, snap: dict[str, Any], label: str = "") -> str:
        self._snap_seq += 1
        sid = f"s{self._snap_seq:04d}"
        snap = dict(snap)
        snap["label"] = label
        snap["ts"] = time.time()
        self.snapshots[sid] = snap
        return sid


def create_session(*, arch: str = "x64", mode: str = "shellcode",
                   engine: str = "speakeasy",
                   flavor: str = "latest") -> EmuSession:
    """Build a new :class:`EmuSession` and register it.

    ``engine`` picks the backend: ``speakeasy`` (default, full Windows
    veneer) or ``unicorn`` (bare CPU). Missing native bindings surface
    as :class:`CodegenUnavailable`.
    """
    if arch not in ("x64", "x86"):
        raise ValueError(f"arch must be x64|x86, got {arch!r}")
    eng_name = engine.lower()
    if eng_name in ("speakeasy", "se"):
        try:
            eng: _Engine = _SpeakeasyEngine(arch, mode=mode, flavor=flavor)
        except CodegenUnavailable:
            raise
        except Exception as exc:
            # Speakeasy's native chain is fragile across Python versions;
            # surface a cleaner error and hint at the escape hatch.
            raise CodegenUnavailable("speakeasy-emulator", exc)
    elif eng_name in ("unicorn", "raw", "uc"):
        eng = _UnicornEngine(arch)
    else:
        raise ValueError(f"unknown engine {engine!r} (speakeasy|unicorn)")

    sid = _next_id()
    session = EmuSession(sid, arch=arch, mode=mode, engine=eng, flavor=flavor)
    EMU_SESSIONS[sid] = session
    return session


def get_session(session_id: str) -> EmuSession:
    s = EMU_SESSIONS.get(session_id)
    if s is None:
        raise KeyError(f"no emulator session with id {session_id!r}")
    s.touch()
    return s


def close_session(session_id: str) -> bool:
    s = EMU_SESSIONS.pop(session_id, None)
    if s is None:
        return False
    try:
        s.engine.close()
    except Exception:  # pragma: no cover
        pass
    return True


def list_sessions() -> list[dict[str, Any]]:
    reap_idle()
    return [s.summary() for s in EMU_SESSIONS.values()]


def reap_idle(ttl_s: float = SESSION_TTL_S) -> int:
    """Close any session that has been idle longer than ``ttl_s`` seconds.
    Returns the number of sessions reaped.
    """
    now = time.time()
    reaped = 0
    for sid, s in list(EMU_SESSIONS.items()):
        if now - s.last_ts > ttl_s:
            close_session(sid)
            reaped += 1
    return reaped


# ---------------------------------------------------------------------------
# Live seeding — pull state from a target and hydrate the emulator.
# ---------------------------------------------------------------------------


async def seed_from_target(session: EmuSession, *, client: Any,
                            view: str, pid: int, tid: int,
                            regions: list[dict[str, Any]],
                            debug_client: Any | None = None) -> dict[str, Any]:
    """Snapshot the live target's regs + selected memory regions and
    load them into the emulator so the caller can single-step from the
    same CPU state the real thread sees.

    ``regions`` is a list of ``{address, size, label}`` dicts (label is
    cosmetic). ``client`` is the connected agent client that services
    ``mem_read``; ``debug_client`` is the client that services ``regs``
    (usually the same object; if ``None``, ``client`` is used for both).
    """
    debug_client = debug_client or client
    holes: list[dict[str, Any]] = []
    bytes_seeded = 0
    regions_loaded = 0
    for region in regions:
        addr = region["address"]
        size = int(region["size"])
        label = region.get("label", "")
        try:
            addr_i = int(addr, 0) if isinstance(addr, str) else int(addr)
        except Exception as exc:
            raise ValueError(f"seed_from_target: bad region address {addr!r}: {exc}")
        try:
            # partial=True is a driver-side per-4KB walk (kernel view
            # only); user-view seeding must use the plain read.
            got = await client.mem_read(pid, addr_i, size, view,
                                          allow_fault=False,
                                          partial=(view == "kernel"),
                                          want_meta=True)
            if isinstance(got, tuple):
                blob, meta = got
                first_bad = int(meta.get("first_bad_offset", 0))
                read_bytes = int(meta.get("read_bytes", len(blob)))
                if read_bytes < size:
                    holes.append({"address": hex(addr_i),
                                   "requested": size,
                                   "got": read_bytes,
                                   "first_bad_offset": first_bad})
            else:
                blob = got
        except Exception as exc:
            holes.append({"address": hex(addr_i),
                           "requested": size,
                           "got": 0,
                           "error": str(exc)})
            continue
        if not blob:
            # Empty read counted as a hole above; nothing to hydrate.
            continue
        try:
            session.engine.mem_map(addr_i, len(blob), "rwx", label)
        except Exception:
            # Region may already be mapped by a prior seed; still write.
            pass
        session.engine.mem_write(addr_i, blob)
        bytes_seeded += len(blob)
        regions_loaded += 1

    # Regs pull — do this last so a partial mem hydration still updates
    # the cursor. Best-effort: any missing register is skipped. The
    # agent's GetRegs RPC has no thread selector — it reports the
    # debugged process's context, so this only hydrates regs when a
    # debug_manage session is attached on the target.
    try:
        if hasattr(debug_client, "debug_regs"):
            raw_regs = await debug_client.debug_regs()
        else:  # pragma: no cover
            raw_regs = await debug_client.regs()
    except Exception as exc:
        raw_regs = {}
        holes.append({"regs_error": str(exc)})
    regs_written: dict[str, int] = {}
    for name, val in (raw_regs or {}).items():
        try:
            iv = int(val, 0) if isinstance(val, str) else int(val)
            regs_written[str(name).lower()] = iv
        except Exception:
            continue
    if regs_written:
        try:
            session.engine.write_regs(regs_written)
            ip_name = "rip" if session.arch == "x64" else "eip"
            if ip_name in regs_written:
                session.cursor = regs_written[ip_name]
        except Exception as exc:
            holes.append({"regs_write_error": str(exc)})

    return {"ok": True,
            "session_id": session.id,
            "regions_loaded": regions_loaded,
            "bytes_seeded": bytes_seeded,
            "holes": holes,
            "regs_written": regs_written,
            "cursor": hex(session.cursor) if session.cursor else "0x0"}
