"""Compact-by-default post-processors + text-line row renderers.

Split out of ``_envelope.py`` (Phase 2b modular split). Holds the
``_strip_mirror_keys`` / ``_collapse_flag_wrappers`` compaction passes,
the per-row ``_text_line_*`` renderers, the ``COMPACT_TRANSFORMS``
registry, and the ``_apply_compact_transform`` dispatcher.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Compact-by-default post-processors
# ---------------------------------------------------------------------------

def _strip_mirror_keys(obj: Any, *, suffix: str) -> Any:
    """Drop every `<key><suffix>` sibling whose bare `<key>` also lives in
    the same dict. `suffix` is `"_int"` for hex mirrors or `"_decoded"` for
    enum siblings. Recurses into nested dicts and lists."""
    if isinstance(obj, dict):
        base_keys = {k for k in obj if not k.endswith(suffix)}
        return {
            k: _strip_mirror_keys(v, suffix=suffix)
            for k, v in obj.items()
            if not (k.endswith(suffix) and k[: -len(suffix)] in base_keys)
        }
    if isinstance(obj, list):
        return [_strip_mirror_keys(x, suffix=suffix) for x in obj]
    return obj


# Keys allowed inside a "flag wrapper" dict. If a dict's keys are a subset
# of this set and it contains "value", it collapses to the bare value.
_FLAG_WRAPPER_KEYS: frozenset[str] = frozenset({
    "value", "source", "note", "confidence", "raw",
})


def _collapse_flag_wrappers(obj: Any) -> Any:
    """Collapse `{value, source, note?, confidence?}` wrappers to the bare
    `value`. `target_manage host_info` and driver-absent status shapes wrap
    every posture bit as such a dict; the wrapper doubles response bytes
    for information the caller rarely uses. Recurses into nested containers.
    """
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if "value" in keys and keys <= _FLAG_WRAPPER_KEYS:
            return obj["value"]
        return {k: _collapse_flag_wrappers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_collapse_flag_wrappers(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# A-2 · Compact text-line collapse (verbosity="compact")
# ---------------------------------------------------------------------------
#
# List-returning actions like ``mem_rw disasm`` / ``vad`` / ``handles`` /
# ``exports`` / ``imports`` / ``heaps`` produce per-row dicts that carry a
# lot of structure a human reader will scan-not-parse anyway. Collapsing
# each row to a single text line at ``verbosity="compact"`` cuts wire
# tokens ~55-70% on a full 64-row disasm and reads a lot better in a
# terminal, without losing information a caller who wanted it structured
# couldn't get back by not passing ``verbosity="compact"``.
#
# Registration is per-``(tool, action)``: a callable that receives the raw
# row list and returns a list of strings. The value in
# :data:`COMPACT_TRANSFORMS` is ``(source_key, callable)``: ``source_key``
# is the key inside ``data`` that holds the row list (``"items"`` for
# actions that go through :func:`list_envelope`, ``"entries"`` /
# ``"heaps"`` for actions that build their own envelope shape).

def _fmt_hex_or_int(v: Any, *, width: int = 0) -> str:
    """Render a value that may already be a hex string (``"0x1234"``) or a
    plain int. ``width`` right-justifies the resulting hex string."""
    if isinstance(v, str):
        s = v
    else:
        try:
            s = hex(int(v))
        except Exception:  # noqa: BLE001 - keep the row printable
            s = str(v)
    return s.rjust(width) if width else s


def _text_line_disasm(rows: list) -> list[str]:
    """``{addr|address, bytes, mnemonic, op_str, size, sym?}`` →
    ``"0x1234  90 90 90       nop"`` (address · bytes · mnemonic · op_str)."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        ea = r.get("address") or r.get("addr") or ""
        ea_s = _fmt_hex_or_int(ea, width=18)
        by = str(r.get("bytes") or "")
        mn = str(r.get("mnemonic") or "")
        op = str(r.get("op_str") or r.get("operands") or "")
        sym = str(r.get("sym") or "")
        line = f"{ea_s}  {by:<24}  {mn} {op}".rstrip()
        if sym:
            line += f"  ; {sym}"
        out.append(line)
    return out


def _text_line_handles(rows: list) -> list[str]:
    """``{handle, type_name, object, name}`` →
    ``"handle=0x8c  type=File  obj=0xffff…  path=..."`` (drops
    ``granted_access`` — callers who care re-run at verbosity="normal")."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        h = _fmt_hex_or_int(r.get("handle") or 0)
        obj = _fmt_hex_or_int(r.get("object") or 0)
        type_name = str(r.get("type_name") or "")
        name = str(r.get("name") or "")
        parts = [f"handle={h}", f"type={type_name}", f"obj={obj}"]
        if name:
            parts.append(f"path={name}")
        out.append("  ".join(parts))
    return out


def _text_line_vad(rows: list) -> list[str]:
    """``{start, end, protect, vad_type, commit_charge}`` →
    ``"0x1234-0x5678  protect=0x40  type=2  commit=4096"``."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        s = _fmt_hex_or_int(r.get("start") or 0)
        e = _fmt_hex_or_int(r.get("end") or 0)
        protect = _fmt_hex_or_int(r.get("protect") or 0)
        vt = r.get("vad_type", 0)
        cc = r.get("commit_charge", 0)
        out.append(
            f"{s}-{e}  protect={protect}  type={vt}  commit={cc}"
        )
    return out


def _text_line_heaps(rows: list) -> list[str]:
    """``{handle, base, committed, reserved, flags, blocks?}`` →
    ``"heap=0x…  base=0x…  committed=… reserved=… flags=0x… blocks=N"``."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        handle = _fmt_hex_or_int(r.get("handle") or 0)
        base = _fmt_hex_or_int(r.get("base") or 0)
        committed = r.get("committed", 0)
        reserved = r.get("reserved", 0)
        flags = _fmt_hex_or_int(r.get("flags") or 0)
        blocks = r.get("blocks") or []
        n_blocks = len(blocks) if isinstance(blocks, list) else 0
        out.append(
            f"heap={handle}  base={base}  committed={committed}  "
            f"reserved={reserved}  flags={flags}  blocks={n_blocks}"
        )
    return out


def _text_line_exports(rows: list) -> list[str]:
    """``{name, ordinal, rva, address, forwarder}`` →
    ``"0x…  ord=N  name  → forwarder"`` (forwarder only when set)."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        addr = _fmt_hex_or_int(r.get("address") or r.get("rva") or 0,
                               width=18)
        ordinal = r.get("ordinal", 0)
        name = str(r.get("name") or "")
        fwd = str(r.get("forwarder") or "")
        line = f"{addr}  ord={ordinal}  {name}"
        if fwd:
            line += f" → {fwd}"
        out.append(line)
    return out


def _text_line_imports(rows: list) -> list[str]:
    """``{dll, name, ordinal, iat_slot, resolved, resolved_module, hooked}``
    → ``"iat_slot=0x…  dll!name  → resolved  [HOOKED]"``."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        iat = _fmt_hex_or_int(r.get("iat_slot") or 0)
        dll = str(r.get("dll") or "")
        name = str(r.get("name") or "")
        ord_num = r.get("ordinal", 0)
        target = name if name else f"#{ord_num}"
        resolved = _fmt_hex_or_int(r.get("resolved") or 0)
        resolved_mod = str(r.get("resolved_module") or "")
        hooked = bool(r.get("hooked"))
        line = f"iat_slot={iat}  {dll}!{target}  → {resolved}"
        if resolved_mod:
            line += f" ({resolved_mod})"
        if hooked:
            line += "  [HOOKED]"
        out.append(line)
    return out


# Keys whose integer values read better as hex (addresses, handles, slots).
# Exact membership — substring matching would catch "value" via "va", etc.
_ADDR_KEYS: frozenset[str] = frozenset({
    "va", "start_va", "win32_start_va", "teb", "base", "base_address",
    "image_base", "address", "addr", "object", "handle", "start", "end",
    "rip", "rsp", "rbp", "ret", "ret_addr", "iat_slot", "resolved", "rva",
    "entry", "stack", "stack_ptr", "ptr", "dr6", "slot",
})


def _text_line_kv(rows: list) -> list[str]:
    """Generic row → ``"k=v k=v ..."`` renderer for list actions without a
    bespoke renderer. Lossless for scalar fields (every non-empty scalar is
    kept); nested dict/list values are dropped (re-request at
    verbosity="full"/"raw" to get them). Int values whose key names an
    address/handle render as hex. Booleans render as a bare flag name when
    true and are omitted when false. Much cheaper than a JSON row and
    scannable in a terminal."""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            out.append(str(r))
            continue
        parts: list[str] = []
        for k, v in r.items():
            if isinstance(v, (dict, list)) or v is None or v == "":
                continue
            if isinstance(v, bool):
                if v:
                    parts.append(str(k))
                continue
            if isinstance(v, int) and k in _ADDR_KEYS:
                parts.append(f"{k}={hex(v)}")
            else:
                parts.append(f"{k}={v}")
        out.append(" ".join(parts))
    return out


# ``source_key`` is the ``data`` sub-key that holds the row list.
#   - ``"items"`` for actions that build via :func:`list_envelope`.
#   - ``"heaps"`` for the ``heaps`` legacy shape.
#   - ``"values"`` for ``reg_manage enum`` (``{subkeys, values}`` shape).
# NOTE: ``modules`` and ``obj_enum`` are intentionally absent — they feed the
# completion-retention hook (tools.common._retain_inventory_from_env), which
# reads dict rows after finalize, so collapsing them to strings would break
# argument completion.
COMPACT_TRANSFORMS: dict[tuple[str, str], tuple[str, Any]] = {
    ("mem_rw", "disasm"):  ("items",   _text_line_disasm),
    ("mem_rw", "handles"): ("items",   _text_line_handles),
    ("mem_rw", "vad"):     ("items",   _text_line_vad),
    ("mem_rw", "heaps"):   ("heaps",   _text_line_heaps),
    ("mem_rw", "exports"): ("items",   _text_line_exports),
    ("mem_rw", "imports"): ("items",   _text_line_imports),
    # v1.0.1: generic kv-collapse for the other high-volume list actions.
    ("mem_rw", "process_list"):     ("items",  _text_line_kv),
    ("mem_rw", "threads"):          ("items",  _text_line_kv),
    ("debug_manage", "threads"):    ("items",  _text_line_kv),
    ("debug_manage", "stacktrace"): ("items",  _text_line_kv),
    ("debug_manage", "regions"):    ("items",  _text_line_kv),
    # bp_manage has no verbosity param, so a caller could not opt back out to
    # structured rows — left uncollapsed (the list is small anyway).
    ("knowledge_manage", "list"):   ("items",  _text_line_kv),
    ("knowledge_manage", "search"): ("items",  _text_line_kv),
    ("reg_manage", "enum"):         ("values", _text_line_kv),
}


def _apply_compact_transform(env: dict) -> None:
    """If ``env`` is registered in :data:`COMPACT_TRANSFORMS`, rewrite the
    row list under ``data[source_key]`` in place. No-op otherwise."""
    key = (env.get("tool"), env.get("action"))
    entry = COMPACT_TRANSFORMS.get(key)  # type: ignore[arg-type]
    if entry is None:
        return
    data = env.get("data")
    if not isinstance(data, dict):
        return
    source_key, fn = entry
    rows = data.get(source_key)
    if not isinstance(rows, list):
        return
    data[source_key] = fn(rows)
