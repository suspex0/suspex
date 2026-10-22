"""v0.17 C1-5 + C2-3: alias-table additions for exec_idapython and
get_struct_member.

Callers naturally reach for `code=` / `script=` on exec_idapython
(canonical: `source`) and for `struct=` / `member=` on
get_struct_member (canonical: `struct_name` / `member_name`) — the
alias rewrite happens shim-side in ``ida_shim_ergo.apply_arg_aliases``,
so we test that helper directly rather than the whole shim.
"""

from __future__ import annotations

import sys
from pathlib import Path


# The helper module lives at orchestrator/ida_shim_ergo.py, next to the
# shim itself, not under `src/`. Add the orchestrator/ dir to the path
# once for the module import below.
_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import ARG_ALIASES, apply_arg_aliases  # noqa: E402


def test_c1_5_exec_idapython_code_aliases_to_source():
    """Alias `code` (JS/Python REPL habit) rewrites to `source`."""
    out = apply_arg_aliases("exec_idapython", {"code": "print(1)"})
    assert out == {"source": "print(1)"}


def test_c1_5_exec_idapython_script_aliases_to_source():
    """Alias `script` (exec_manage neighbour habit) rewrites to `source`."""
    out = apply_arg_aliases("exec_idapython", {"script": "print(1)"})
    assert out == {"source": "print(1)"}


def test_c1_5_exec_idapython_canonical_wins():
    """Both alias and canonical present: keep canonical, drop alias."""
    out = apply_arg_aliases(
        "exec_idapython", {"code": "IGNORED", "source": "print(1)"}
    )
    assert out == {"source": "print(1)"}


def test_c1_5_exec_idapython_canonical_unchanged():
    """Canonical-only input passes through untouched."""
    out = apply_arg_aliases("exec_idapython", {"source": "print(1)"})
    assert out == {"source": "print(1)"}


def test_c1_5_get_struct_member_short_aliases():
    """C2-3: short `struct` / `member` rewrite to canonical names."""
    out = apply_arg_aliases(
        "get_struct_member",
        {"struct": "_EPROCESS", "member": "Pcb"},
    )
    assert out == {"struct_name": "_EPROCESS", "member_name": "Pcb"}


def test_c1_5_get_struct_member_canonical_wins():
    """Canonical + alias supplied for one field: keep canonical, drop alias."""
    out = apply_arg_aliases(
        "get_struct_member",
        {"struct": "IGNORED", "struct_name": "_EPROCESS", "member": "Pcb"},
    )
    assert out == {"struct_name": "_EPROCESS", "member_name": "Pcb"}


def test_c1_5_alias_registry_carries_new_tools():
    """Fast tripwire: the two new alias tables ship in the registry."""
    assert "exec_idapython" in ARG_ALIASES
    assert ARG_ALIASES["exec_idapython"] == {
        "code": "source", "script": "source",
    }
    assert "get_struct_member" in ARG_ALIASES
    assert ARG_ALIASES["get_struct_member"] == {
        "struct": "struct_name", "member": "member_name",
    }
