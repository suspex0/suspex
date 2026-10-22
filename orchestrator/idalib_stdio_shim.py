"""idalib_stdio_shim.py — thin facade over the ``idalib_shim`` package.

The original 1500-line module was split into ``orchestrator/idalib_shim/``
(see the ``docs/`` note and ``.kilo/plans/2026-09-17-modular-split.md``).
This file exists so:

* ``configs/local.yaml`` can keep launching the shim by its original path
  (``python .../idalib_stdio_shim.py``) — importing this module runs
  ``__main__`` when invoked as a script.
* Legacy imports of ``idalib_stdio_shim`` from tests / bridge glue keep
  seeing every public name they used before the split.

No logic lives here — every function, dict, lock and constant is
re-exported from the ``idalib_shim`` submodules.
"""
from __future__ import annotations

# ``mcp.types`` was previously bound as ``types`` at module level; the
# JOBS test suite reaches through the shim to build synthetic content
# lists (``shim.types.TextContent(...)``), so keep the alias.
import mcp.types as types  # noqa: F401

# Constants / knobs.
from idalib_shim.backend import (  # noqa: F401
    POLL_INTERVAL_S,
    READY_TIMEOUT_S,
    _backend_cmd,
    _backend_exe,
    _backend_names,
    _dump_startup_env,
    _free_port,
    _prevalidate_pe,
)
from idalib_shim.dispatch import (  # noqa: F401
    _call_passthrough,
    _call_tool,
    _fetch_nearest_function,
    _ida_job_cancel,
    _ida_job_list,
    _ida_job_start,
    _ida_job_status,
    _ida_result,
    _try_decompile_disasm_fallback,
)
from idalib_shim.envelopes import (  # noqa: F401
    _chunked_envelope,
    _pending_envelope,
)
from idalib_shim.jobs import (  # noqa: F401
    CHUNK_BYTES,
    JOB_RETENTION_S,
    JOBS,
    JOBS_LOCK,
    SOFT_DEADLINE_S,
    _chunk_count,
    _prune_jobs_locked,
    _shim_spill_dir,
    _spawn_job,
    _stash_result,
    _write_listing_spill,
)
from idalib_shim.listing import (  # noqa: F401
    BACKEND_TOOL_META,
    BACKEND_TOOLS,
    PREVIEW_BYTES,
    _flat_text_from_content,
    _list_tools,
    _log_tail,
    _maybe_populate_schemas,
    _preview,
    _result_text,
    server,
)
from idalib_shim.logging import _log, _tail_log  # noqa: F401
from idalib_shim.sessions import (  # noqa: F401
    ALIASES,
    BY_PATH,
    LOCKS,
    REG_LOCK,
    SESSIONS,
    STACKS,
    _cleanup,
    _close,
    _kill,
    _list,
    _open,
    _open_locked,
    _probe_alive,
    _reap_dead,
    _resolve,
    _sess_payload,
)
from idalib_shim.transforms import (  # noqa: F401
    _apply_response_transforms,
    _coerce_none_string_fields,
    _pop_transformer_args,
)

# ``main`` lives in the ``__main__`` submodule; expose it here for the
# ``python idalib_stdio_shim.py`` script-path invocation used by
# ``configs/local.yaml``.
from idalib_shim.__main__ import main  # noqa: F401


if __name__ == "__main__":
    import anyio

    anyio.run(main)
