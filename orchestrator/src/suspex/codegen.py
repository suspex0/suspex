"""Optional codegen integration (extra: ``pip install suspex0[codegen]``).

Wraps ``capstone`` (disassembly) and ``keystone`` (assembly) behind a soft
import so the core stack keeps working without the extra installed. Every
public entry point raises :class:`CodegenUnavailable` on the first call
when the underlying binding is missing, so the MCP layer can turn the
error into the standard ``{ok:false, kind:"codegen_extra_missing", ...}``
envelope without the whole server refusing to start.

Follows the same shape as :mod:`suspex.yara` (soft import + ``available``
flag + named error on first use).
"""

from __future__ import annotations

from typing import Any

# --- Soft-import bookkeeping ----------------------------------------------
_CAPSTONE: Any = None
_KEYSTONE: Any = None
_UNICORN: Any = None
_SPEAKEASY: Any = None

# Cached engine handles keyed by ``(arch, syntax|mode)``. Building a
# capstone/keystone engine is not free — a couple of ms per call adds up
# on batched disasm loops.
_CS_CACHE: dict[tuple[str, str], Any] = {}
_KS_CACHE: dict[str, Any] = {}


class CodegenUnavailable(RuntimeError):
    """Raised on first use of a codegen backend that isn't installed.

    The tool layer catches this and turns it into
    ``{ok:false, kind:"codegen_extra_missing", error:..., hint:...}``.
    """

    def __init__(self, backend: str, cause: Exception | None = None) -> None:
        msg = f"{backend} not installed (pip install suspex0[codegen])"
        if cause is not None:
            msg = f"{msg} — import failed: {type(cause).__name__}: {cause}"
        super().__init__(msg)
        self.backend = backend
        self.kind = "codegen_extra_missing"
        self.hint = ("install the codegen extra: "
                     "pip install 'suspex0[codegen]' (or "
                     "uv sync --extra codegen)")


def _load_capstone() -> Any:
    global _CAPSTONE
    if _CAPSTONE is None:
        try:
            import capstone  # type: ignore
        except Exception as exc:  # pragma: no cover - exercised without extra
            raise CodegenUnavailable("capstone", exc)
        _CAPSTONE = capstone
    return _CAPSTONE


def _load_keystone() -> Any:
    global _KEYSTONE
    if _KEYSTONE is None:
        try:
            import keystone  # type: ignore
        except Exception as exc:  # pragma: no cover - exercised without extra
            raise CodegenUnavailable("keystone-engine", exc)
        _KEYSTONE = keystone
    return _KEYSTONE


def _load_unicorn() -> Any:
    global _UNICORN
    if _UNICORN is None:
        try:
            import unicorn  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise CodegenUnavailable("unicorn", exc)
        _UNICORN = unicorn
    return _UNICORN


def _load_speakeasy() -> Any:
    global _SPEAKEASY
    if _SPEAKEASY is None:
        try:
            import speakeasy  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise CodegenUnavailable("speakeasy-emulator", exc)
        _SPEAKEASY = speakeasy
    return _SPEAKEASY


def capstone_available() -> bool:
    try:
        _load_capstone()
        return True
    except CodegenUnavailable:
        return False


def keystone_available() -> bool:
    try:
        _load_keystone()
        return True
    except CodegenUnavailable:
        return False


def unicorn_available() -> bool:
    try:
        _load_unicorn()
        return True
    except CodegenUnavailable:
        return False


def speakeasy_available() -> bool:
    try:
        _load_speakeasy()
        return True
    except CodegenUnavailable:
        return False


# --- Arch / syntax normalization ------------------------------------------

_ARCH_ALIASES = {
    "x64": "x64", "amd64": "x64", "x86_64": "x64", "x86-64": "x64", "64": "x64",
    "x86": "x86", "i386": "x86", "ia32": "x86", "32": "x86",
}
_SYNTAX_ALIASES = {
    "intel": "intel", "nasm": "intel",
    "att": "att", "at&t": "att", "gas": "att",
}


class CodegenArgError(ValueError):
    """Bad argument (not a missing dep). Kept lightweight so the tool layer
    can distinguish arg errors from missing-extra errors."""

    def __init__(self, arg: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.arg = arg
        self.kind = "bad_arg"
        self.hint = hint


def canonical_arch(arch: str) -> str:
    a = (arch or "x64").strip().lower()
    if a not in _ARCH_ALIASES:
        raise CodegenArgError("arch",
                               f"unknown arch {arch!r}",
                               "arch must be x64|x86 (aliases: amd64, i386)")
    return _ARCH_ALIASES[a]


def canonical_syntax(syntax: str) -> str:
    s = (syntax or "intel").strip().lower()
    if s not in _SYNTAX_ALIASES:
        raise CodegenArgError("syntax",
                               f"unknown syntax {syntax!r}",
                               "syntax must be intel|att")
    return _SYNTAX_ALIASES[s]


# --- Capstone wrappers -----------------------------------------------------

def _cs_engine(arch: str, syntax: str) -> Any:
    key = (arch, syntax)
    eng = _CS_CACHE.get(key)
    if eng is not None:
        return eng
    cs = _load_capstone()
    mode = cs.CS_MODE_64 if arch == "x64" else cs.CS_MODE_32
    eng = cs.Cs(cs.CS_ARCH_X86, mode)
    eng.detail = False
    if syntax == "att":
        eng.syntax = cs.CS_OPT_SYNTAX_ATT
    _CS_CACHE[key] = eng
    return eng


def disasm(data: bytes, arch: str = "x64", *,
           syntax: str = "intel", address: int = 0,
           count: int = 64, detail: bool = False) -> list[dict[str, Any]]:
    """Disassemble ``data`` into a list of instruction dicts.

    Returns at most ``count`` instructions. Each dict carries
    ``addr, bytes, mnemonic, op_str, size`` and, when ``detail=True``,
    ``groups``, ``regs_read``, ``regs_write``, ``operands``.
    """
    a = canonical_arch(arch)
    s = canonical_syntax(syntax)
    eng = _cs_engine(a, s)
    prev_detail = eng.detail
    if detail != prev_detail:
        eng.detail = detail
    try:
        out: list[dict[str, Any]] = []
        for i, ins in enumerate(eng.disasm(bytes(data), address)):
            if i >= count:
                break
            row: dict[str, Any] = {
                "addr": ins.address,
                "bytes": bytes(ins.bytes).hex(),
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
                "size": ins.size,
            }
            if detail:
                try:
                    row["groups"] = [eng.group_name(g) for g in ins.groups]
                    row["regs_read"] = [eng.reg_name(r) for r in ins.regs_read]
                    row["regs_write"] = [eng.reg_name(r) for r in ins.regs_write]
                    row["operands"] = [
                        {"type": op.type,
                         "size": op.size,
                         "access": getattr(op, "access", 0)}
                        for op in ins.operands
                    ]
                except Exception:  # pragma: no cover - detail is best-effort
                    pass
            out.append(row)
        return out
    finally:
        if eng.detail != prev_detail:
            eng.detail = prev_detail


def _ks_engine(arch: str) -> Any:
    eng = _KS_CACHE.get(arch)
    if eng is not None:
        return eng
    ks = _load_keystone()
    mode = ks.KS_MODE_64 if arch == "x64" else ks.KS_MODE_32
    eng = ks.Ks(ks.KS_ARCH_X86, mode)
    # Keystone defaults to Intel; symbol-resolver hook set separately by
    # callers that need it. Kept lazy so `_KS_CACHE` stays small.
    _KS_CACHE[arch] = eng
    return eng


class AssembleError(RuntimeError):
    """Raised on a Keystone syntax/encoding failure. Carries the raw
    Keystone message so the LLM can fix the mnemonic. Distinct from
    :class:`CodegenUnavailable` — the extra IS installed, the source is bad.
    """

    def __init__(self, message: str, *, count: int = 0, hint: str = "") -> None:
        super().__init__(message)
        self.count = count  # instructions successfully assembled before failure
        self.kind = "assemble_error"
        self.hint = hint or ("check mnemonic syntax; keystone accepts "
                             "nasm-style intel by default")


def _is_label_line(ln: str) -> bool:
    """True when ``ln`` looks like a bare label (``name:``, no other text)."""
    if not ln.endswith(":"):
        return False
    head = ln[:-1].strip()
    if not head:
        return False
    # Reject spaces/tabs inside the identifier and anything that isn't a
    # C-ish identifier char (labels commonly are [A-Za-z_.][A-Za-z0-9_.]*).
    for ch in head:
        if ch.isalnum() or ch in ("_", ".", "$"):
            continue
        return False
    return True


def assemble(code: str, arch: str = "x64", *,
             address: int = 0) -> tuple[bytes, int, dict[str, int]]:
    """Assemble ``code`` (multi-line, labels allowed) at ``address``.

    Returns ``(bytes, ins_count, labels)``. ``labels`` maps every bare
    ``name:`` marker to its resolved VA when the label map can be
    computed cheaply; when line-by-line pre-scan would fail (forward
    references, multi-line directives), ``labels`` comes back empty
    but the assembled bytes are still returned from the one-shot call.
    """
    a = canonical_arch(arch)
    eng = _ks_engine(a)
    ks = _load_keystone()

    start = int(address or 0)

    # Fast path: one shot into keystone. Handles forward references,
    # multi-line directives, everything the underlying engine supports.
    try:
        encoding, count = eng.asm(code, addr=start)
    except ks.KsError as exc:
        raise AssembleError(f"keystone: {exc}",
                            hint="check mnemonic syntax; keystone accepts "
                                 "nasm-style intel by default") from exc
    if encoding is None:
        raise AssembleError("keystone: nothing assembled (empty output)",
                            count=0)

    out_bytes = bytes(encoding)
    ins_count = int(count or 0)

    # Best-effort label map. Only build it when the source actually has
    # bare label lines; otherwise skip the extra work entirely.
    stripped = [ln.strip() for ln in code.splitlines()]
    if not any(_is_label_line(ln) for ln in stripped):
        return out_bytes, ins_count, {}

    labels: dict[str, int] = {}
    cur = start
    ok = True
    for raw in stripped:
        if not raw or raw.startswith(";") or raw.startswith("#"):
            continue
        if _is_label_line(raw):
            labels[raw[:-1].strip()] = cur
            continue
        try:
            enc2, _ = eng.asm(raw, addr=cur)
        except ks.KsError:
            # Forward reference or directive we can't assemble in
            # isolation; give up on the label map, keep the bytes.
            ok = False
            break
        if enc2 is None:
            ok = False
            break
        cur += len(enc2)
    return out_bytes, ins_count, labels if ok else {}
