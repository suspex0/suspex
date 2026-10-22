"""Entry facade for the suspex pyghidra backend (thin wrapper).

Mirrors ``suspex_idalib_ext.py``'s role on the IDA side: the shim
spawns ``python suspex_pyghidra_ext.py --port N --project-dir ...``
and this script's directory lands on ``sys.path[0]`` so
``pyghidra_ext.*`` imports resolve without packaging.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_HERE = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

from pyghidra_ext.main import main  # noqa: E402

if __name__ == "__main__":
    _sys.exit(main() or 0)
