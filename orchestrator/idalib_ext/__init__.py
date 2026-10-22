"""Modular split of suspex_idalib_ext.

The facade at ``orchestrator/suspex_idalib_ext.py`` re-exports every
public name from this package and is still what the idalib stdio shim
path-loads (``python suspex_idalib_ext.py <input> --port <port>``).
Module-level split; no logic changes.
"""
