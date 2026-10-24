"""v0.31 Phase 1.7 — known-globals signature pack.

A curated set of byte patterns that locate exported-but-unnamed kernel
globals (ObpRootDirectoryObject, PsLoadedModuleList, KdDebuggerDataBlock,
KdpDmTransport, ...) when the PDB server has nothing to say about the
build. Each entry carries:

- ``module``: the image the pattern lives in (ntoskrnl.exe, ...)
- ``name``: the global the match recovers
- ``arch``: `x64` / `x86`
- ``pattern``: IDA-style byte pattern string, e.g. ``48 8B 05 ?? ?? ?? ??``
  — matches the ``mov rax, [rip+disp32]`` prologue that loads the global.
- ``rip_rel_disp_offset``: offset into the match where the signed 32-bit
  rip-relative displacement starts; the resolver adds that displacement
  to the instruction's end to recover the global's VA.
- ``build_min`` / ``build_max``: optional NT build-number range the
  pattern is known-good for (both inclusive; `0` means unbounded).

Confidence is derived from how many patterns matched (one hit = `low`,
same VA from two or more = `high`). Callers that need audit-grade
certainty should still prefer PDB symbols; the pattern pack is the
fallback for a sealed box with no symbol server.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PatternEntry:
    module: str
    name: str
    arch: str
    pattern: str
    rip_rel_disp_offset: int = 3  # ``48 8B 05 <disp32>`` = 3
    build_min: int = 0
    build_max: int = 0
    note: str = ""


# Seed pack — the globals the plan calls out plus a couple of common
# neighbors. Signatures are intentionally short and permissive; a
# post-match validator (readback, type check) is the caller's job.
KNOWN_GLOBALS: tuple[PatternEntry, ...] = (
    # ObpRootDirectoryObject: referenced from ObpLookupObjectName's prologue
    # as ``mov rax, cs:ObpRootDirectoryObject`` (``48 8B 05 ?? ?? ?? ??``).
    PatternEntry(
        module="ntoskrnl.exe",
        name="ObpRootDirectoryObject",
        arch="x64",
        pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0",
    ),
    # PsLoadedModuleList: ``lea rcx, cs:PsLoadedModuleList`` /
    # ``48 8D 0D ?? ?? ?? ??`` immediately before a flink walk.
    PatternEntry(
        module="ntoskrnl.exe",
        name="PsLoadedModuleList",
        arch="x64",
        pattern="48 8D 0D ?? ?? ?? ?? 48 8B 11",
    ),
    # KdDebuggerDataBlock: Kintsugi-style prologue — ``mov rax, cs:KdDebuggerDataBlock``.
    PatternEntry(
        module="ntoskrnl.exe",
        name="KdDebuggerDataBlock",
        arch="x64",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 40 10",
    ),
    # KdpDmTransport: debugger transport descriptor; narrow sig.
    PatternEntry(
        module="ntoskrnl.exe",
        name="KdpDmTransport",
        arch="x64",
        pattern="48 8D 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? C3",
    ),
)


def pack_entries(module: str = "", name: str = "", arch: str = "x64",
                 build: int = 0) -> list[PatternEntry]:
    """Entries matching the (module, name, arch) filter and the build
    range when supplied. Empty strings mean "any"."""
    out: list[PatternEntry] = []
    for e in KNOWN_GLOBALS:
        if module and module.lower() != e.module.lower():
            continue
        if name and e.name != name:
            continue
        if arch and e.arch != arch:
            continue
        if build:
            if e.build_min and build < e.build_min:
                continue
            if e.build_max and build > e.build_max:
                continue
        out.append(e)
    return out


def parse_pattern(pat: str) -> tuple[bytes, bytes]:
    """Return (needle, mask) for an IDA-style byte pattern. mask bytes
    are 0xFF where the needle byte is literal, 0x00 where it is '??'."""
    needle = bytearray()
    mask = bytearray()
    for tok in pat.split():
        if tok == "??" or tok == "?":
            needle.append(0)
            mask.append(0)
        else:
            needle.append(int(tok, 16))
            mask.append(0xFF)
    return bytes(needle), bytes(mask)


def disp_at(data: bytes, offset: int, length: int = 4,
            signed: bool = True) -> int:
    """Little-endian integer at ``data[offset:offset+length]``."""
    return int.from_bytes(data[offset:offset + length], "little",
                          signed=signed)
