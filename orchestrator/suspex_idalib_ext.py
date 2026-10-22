"""Extension entry over ida-pro-mcp's idalib_server (thin facade).

Adds two tools the vanilla backend is missing but that the reviewer of
the EDID engagement said were required for vtable-dispatched code:

* `create_function(address)` — force IDA to carve a function at an
  address auto-analysis missed (nvlddmkm's display stack case: known
  ea from strings/xrefs, but no direct caller so no function).
* `exec_idapython(source)` — run arbitrary IDAPython in the analyst
  session; captures stdout/stderr and an optional `result` local. The
  escape hatch that removes any need to open GUI IDA for one-off tasks.
* `idb_save` / `ida_status` / `ida_query_context` — force-checkpoint
  with an input-path-safe target, structured analysis snapshot, and
  one-shot empty-result disambiguation (addr_in_db / analysis_state).

Also patches `idapro.open_database` so setting `SUSPX_IDA_NO_AUTO=1`
in the child env skips run_auto_analysis — the vanilla server hardcodes
`True` and auto-analysis on a 100 MB driver can burn 20-40 min per open.
The shim sets this env var when the caller passes
`run_auto_analysis=false` on `ida_manage(action='open'/'open_async')`.

`idapro.save_database` is patched process-wide to refuse/redirect any
save that would overwrite the input binary (real data-loss bug: a hook
calling `save_database(input.sys)` replaced the .sys with packed IDA2
bytes mid-analysis). Every save is forced onto `<input>.i64`.

Runs by calling `ida_pro_mcp.idalib_server.main()` after registration.

This module is a thin facade that re-exports every public name from the
:mod:`idalib_ext` package (funcs/scan/typeinfo/layout/save/status/main).
It remains the script that ``idalib_stdio_shim.py`` path-loads with
``python suspex_idalib_ext.py <input> --port <port>``, and remains the
import surface every test uses (``importlib.import_module("suspex_idalib_ext")``).
No logic changes vs the pre-split single-file version.
"""
from __future__ import annotations

import os as _os
import sys as _sys

# Path-loaded entry: when ``idalib_stdio_shim.py`` spawns us as
# ``python suspex_idalib_ext.py <input> --port <port>``, the script's
# directory (the orchestrator root) is already on ``sys.path[0]``. When
# imported as a module from tests or the shim in-process the caller
# adds the orchestrator dir themselves. Both paths make
# ``idalib_ext.*`` importable without further wiring.
_HERE = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

# ida_pro_mcp is re-exported so ``suspex_idalib_ext._core`` still resolves
# to the vendored server module for anything that reached in behind our
# back (there was one such call site before the split).
import ida_pro_mcp.idalib_server as _core  # noqa: E402

from idalib_ext.funcs import (  # noqa: E402
    _EXEC_RESULT_CAP_BYTES,
    _coerce_json_safe,
    _member_offset_size,
    _resolve_offset_recursive,
    _to_ea,
    create_function,
    get_struct_member,
    hex_ea,
    resolve_offset,
)
from idalib_ext.layout import (  # noqa: E402
    _dump_enum_layout,
    _dump_struct_layout,
    _iter_named_types,
    _pdb_cache_dir,
    _safe_cache_component,
    dump_layout,
)
from idalib_ext.main import main  # noqa: E402
from idalib_ext.save import (  # noqa: E402
    _patch_no_auto,
    _patch_safe_save,
    _record_input_path,
    _safe_save_target,
    _spawn_periodic_saver,
    exec_idapython,
    idb_save,
)
from idalib_ext.scan import (  # noqa: E402
    _parse_hex_pattern,
    _scan_masked,
    pattern_scan,
    qword_value_scan,
)
from idalib_ext.status import ida_query_context, ida_status  # noqa: E402
from idalib_ext.typeinfo import (  # noqa: E402
    _enum_info_classic,
    _enum_info_tif,
    list_functions_filter,
    type_info,
)

# ``_INPUT_PATH_FOR_SAVE`` lives on :mod:`idalib_ext.save` as a mutable
# module-level; expose it through the facade via a property-style
# ``__getattr__`` so callers that reached in (tests, ad hoc scripts)
# still see the current value after ``_record_input_path`` fires.
from idalib_ext import funcs as _funcs_mod  # noqa: E402
from idalib_ext import save as _save_mod  # noqa: E402


def __getattr__(name: str):  # PEP 562 module-level attribute hook
    if name == "_INPUT_PATH_FOR_SAVE":
        return _save_mod._INPUT_PATH_FOR_SAVE
    raise AttributeError(name)


# Mutable-attribute parity: pre-split, tests monkeypatched
# ``_EXEC_RESULT_CAP_BYTES`` on this module and ``_coerce_json_safe``
# (defined in the same module) saw the change immediately. After the
# split ``_coerce_json_safe`` reads the constant from
# :mod:`idalib_ext.funcs`, so a naked setattr on the facade would be a
# silent no-op. Route any assignment to ``_EXEC_RESULT_CAP_BYTES`` on
# this module through to :mod:`idalib_ext.funcs` so the pre-split
# monkeypatch contract still holds. Uses the PEP 562 replace-the-class
# trick for module ``__setattr__`` — no logic change to the function.
import types as _types  # noqa: E402


class _Facade(_types.ModuleType):
    def __setattr__(self, name: str, value):  # noqa: D401 - see above
        _types.ModuleType.__setattr__(self, name, value)
        if name == "_EXEC_RESULT_CAP_BYTES":
            _funcs_mod._EXEC_RESULT_CAP_BYTES = value


_sys.modules[__name__].__class__ = _Facade


__all__ = [
    # funcs
    "_EXEC_RESULT_CAP_BYTES",
    "_coerce_json_safe",
    "_member_offset_size",
    "_resolve_offset_recursive",
    "_to_ea",
    "create_function",
    "get_struct_member",
    "hex_ea",
    "resolve_offset",
    # scan
    "_parse_hex_pattern",
    "_scan_masked",
    "pattern_scan",
    "qword_value_scan",
    # typeinfo
    "_enum_info_classic",
    "_enum_info_tif",
    "list_functions_filter",
    "type_info",
    # layout
    "_dump_enum_layout",
    "_dump_struct_layout",
    "_iter_named_types",
    "_pdb_cache_dir",
    "_safe_cache_component",
    "dump_layout",
    # save + exec
    "_patch_no_auto",
    "_patch_safe_save",
    "_record_input_path",
    "_safe_save_target",
    "_spawn_periodic_saver",
    "exec_idapython",
    "idb_save",
    # status
    "ida_query_context",
    "ida_status",
    # entrypoint
    "main",
]


if __name__ == "__main__":
    _sys.exit(main() or 0)
