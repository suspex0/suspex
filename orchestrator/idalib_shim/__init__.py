"""idalib_shim - modular split of idalib_stdio_shim.py.

This package is the split of the original ``orchestrator/idalib_stdio_shim.py``.
The public surface is preserved via the top-level facade at
``orchestrator/idalib_stdio_shim.py`` which re-exports everything from
here.  See ``idalib_shim.__main__`` for the ``main()`` entrypoint.

No logic changes vs. the pre-split module — only mechanical relocation.
"""
from __future__ import annotations
