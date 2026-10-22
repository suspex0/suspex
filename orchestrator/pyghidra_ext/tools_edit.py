"""Mutation tool bodies — rename/retype/comment/patch, all wrapped in
Ghidra transactions so the edits persist through program_save."""
from __future__ import annotations

from typing import Any

from .helpers import _addr_str, _decompile, _err, _resolve_target
from .state import STATE, _j


def _source_type(name: str = "USER_DEFINED"):
    from ghidra.program.model.symbol import SourceType
    return getattr(SourceType, name, SourceType.USER_DEFINED)


def _transaction(program: Any, label: str):
    class _Tx:
        def __enter__(self):
            self.tx = program.startTransaction(label)
            self.ok = False
            return self
        def __exit__(self, exc_type, exc, tb):
            program.endTransaction(self.tx, exc_type is None and self.ok)
            return False
    return _Tx()


def rename_function(binary_name: str, name_or_address: Any = None,
                    new_name: str = "", address: Any = None) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    f = STATE.get_function(
        p, name_or_address if name_or_address is not None else address)
    if f is None:
        return _j(_err("not_found", "no function resolved"))
    old = f.getName()
    with STATE.lock, _transaction(p, "rename_function") as tx:
        try:
            f.setName(new_name, _source_type())
            tx.ok = True
        except Exception as exc:  # noqa: BLE001
            return _j(_err("rename_failed", f"{type(exc).__name__}: {exc}"))
    return _j({"ok": True, "old_name": old, "new_name": f.getName(),
               "entry": _addr_str(f.getEntryPoint())})


def rename_variable(binary_name: str, function_name_or_address: Any = None,
                    variable_name: str = "", new_name: str = "",
                    # ida-side spelling accepted
                    name_or_address: Any = None) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    f = STATE.get_function(
        p, function_name_or_address
        if function_name_or_address is not None else name_or_address)
    if f is None:
        return _j(_err("not_found", "no function resolved"))
    var = None
    try:
        for v in f.getAllVariables():
            if v.getName() == variable_name:
                var = v
                break
    except Exception:  # noqa: BLE001
        pass
    if var is None:
        # fall back to the decompiler's local-variable view (high func)
        res = _decompile(p, f)
        if res is not None and res.getHighFunction() is not None:
            lsm = res.getHighFunction().getLocalSymbolMap()
            try:
                for s in lsm.getSymbols():
                    if s.getName() == variable_name:
                        var = s.getHighVariable()
                        break
            except Exception:  # noqa: BLE001
                var = None
        if var is None:
            return _j(_err("not_found",
                           f"variable {variable_name!r} not found in "
                           f"{f.getName()}"))
    with STATE.lock, _transaction(p, "rename_variable") as tx:
        try:
            var.setName(new_name, _source_type())
            tx.ok = True
        except Exception as exc:  # noqa: BLE001
            return _j(_err("rename_failed",
                           f"{type(exc).__name__}: {exc} — "
                           "HighVariable rename may need a decompiler "
                           "commit; try exec_ghidra_script"))
    return _j({"ok": True, "function": f.getName(),
               "old_name": variable_name, "new_name": new_name})


def _resolve_datatype(program: Any, type_name: str):
    dtm = program.getDataTypeManager()
    dt = dtm.getDataType(type_name)
    if dt is not None:
        return dt
    # search all DTMs (built-in + archives) via the parser
    try:
        from ghidra.app.util.cparser.C import CParserUtils
        dt = CParserUtils.parseDataType(type_name, None, program)
        if dt is not None:
            return dt
    except Exception:  # noqa: BLE001
        pass
    it = dtm.getAllDataTypes()
    while it.hasNext():
        d = it.next()
        if d.getName() == type_name:
            return d
    return None


def set_variable_type(binary_name: str,
                      function_name_or_address: Any = None,
                      variable_name: str = "", type_name: str = "",
                      name_or_address: Any = None) -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    f = STATE.get_function(
        p, function_name_or_address
        if function_name_or_address is not None else name_or_address)
    if f is None:
        return _j(_err("not_found", "no function resolved"))
    var = None
    for v in f.getAllVariables():
        if v.getName() == variable_name:
            var = v
            break
    if var is None:
        return _j(_err("not_found",
                       f"variable {variable_name!r} not found — Ghidra "
                       "locals created by the decompiler may need "
                       "set_variable_type via exec_ghidra_script"))
    dt = _resolve_datatype(p, type_name)
    if dt is None:
        return _j(_err("not_found", f"datatype {type_name!r} not found"))
    with STATE.lock, _transaction(p, "set_variable_type") as tx:
        try:
            var.setDataType(dt, _source_type())
            tx.ok = True
        except Exception as exc:  # noqa: BLE001
            return _j(_err("retype_failed", f"{type(exc).__name__}: {exc}"))
    return _j({"ok": True, "function": f.getName(),
               "variable": variable_name, "type": str(dt)})


def set_function_prototype(binary_name: str,
                           function_name_or_address: Any = None,
                           prototype: str = "",
                           name_or_address: Any = None) -> str:
    """Apply a C prototype ('NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)')
    via Ghidra's C signature parser."""
    st = STATE.get(binary_name)
    p = st["program"]
    f = STATE.get_function(
        p, function_name_or_address
        if function_name_or_address is not None else name_or_address)
    if f is None:
        return _j(_err("not_found", "no function resolved"))
    with STATE.lock, _transaction(p, "set_function_prototype") as tx:
        try:
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.listing import Function as _F
            fd = CParserUtils.parseSignature(None, p, prototype, False)
            if fd is None:
                return _j(_err("parse_failed",
                               f"could not parse {prototype!r}"))
            f.updateFunction(None, fd.getReturnType(),
                             list(fd.getArguments()),
                             _F.FunctionUpdateType.CUSTOM_STORAGE)
            tx.ok = True
        except Exception as exc:  # noqa: BLE001
            return _j(_err("prototype_failed",
                           f"{type(exc).__name__}: {exc} — "
                           "fallback: exec_ghidra_script"))
    return _j({"ok": True, "function": f.getName(),
               "signature": str(f.getSignature())})


_COMMENT_TYPES = {
    "eol": "EOL_COMMENT", "end_of_line": "EOL_COMMENT",
    "plate": "PLATE_COMMENT", "pre": "PRE_COMMENT",
    "post": "POST_COMMENT", "repeatable": "REPEATABLE_COMMENT",
}


def set_comment(binary_name: str, target: str = "",
                comment: str = "", comment_type: str = "eol",
                address: str = "") -> str:
    st = STATE.get(binary_name)
    p = st["program"]
    tgt = target or address
    addr = STATE.to_addr(p, tgt)
    ct = _COMMENT_TYPES.get(str(comment_type).lower(), "EOL_COMMENT")
    code_unit = p.getListing().getCodeUnitAt(addr)
    if code_unit is None:
        return _j(_err("not_found", f"no code unit at {tgt}"))
    import ghidra.program.model.listing as _gl
    const = getattr(_gl.CodeUnit, ct)
    with STATE.lock, _transaction(p, "set_comment") as tx:
        code_unit.setComment(const, comment)
        tx.ok = True
    return _j({"ok": True, "address": _addr_str(addr),
               "comment_type": ct})


def patch_bytes(binary_name: str, address: str = "",
                hex_bytes: str = "", verify: bool = True) -> str:
    """Write raw bytes into program memory inside a transaction.
    ``hex_bytes`` space-separated or contiguous hex."""
    st = STATE.get(binary_name)
    p = st["program"]
    addr = STATE.to_addr(p, address)
    raw = bytes.fromhex(hex_bytes.replace(" ", ""))
    if not raw:
        return _j(_err("bad_arg", "hex_bytes empty"))
    mem = p.getMemory()
    with STATE.lock, _transaction(p, "patch_bytes") as tx:
        try:
            mem.setBytes(addr, raw)
            tx.ok = True
        except Exception as exc:  # noqa: BLE001
            return _j(_err("patch_failed", f"{type(exc).__name__}: {exc}"))
    out = {"ok": True, "address": _addr_str(addr), "size": len(raw)}
    if verify:
        buf = bytearray(len(raw))
        mem.getBytes(addr, buf)
        out["verified"] = bytes(buf) == raw
    return _j(out)
