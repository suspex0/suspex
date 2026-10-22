"""ghidra_stdio_shim.py — thin facade over the ``ghidra_shim`` package.

Sibling of ``idalib_stdio_shim.py``: the bridge launches this file by
path (``python .../ghidra_stdio_shim.py``) exactly the way it launches
the IDA shim, and tests can reach the same public names.

No logic lives here — everything is re-exported from ``ghidra_shim``.
"""
from __future__ import annotations

import mcp.types as types  # noqa: F401

# Constants / knobs.
from ghidra_shim.backend import (  # noqa: F401
    POLL_INTERVAL_S,
    READY_TIMEOUT_S,
    _backend_cmd,
    _backend_env,
    _backend_names,
    _backend_python,
    _dump_startup_env,
    _free_port,
)
from ghidra_shim.dispatch import (  # noqa: F401
    _call_passthrough,
    _call_tool,
    _fetch_nearest_function,
    _ghidra_job_cancel,
    _ghidra_job_list,
    _ghidra_job_start,
    _ghidra_job_status,
    _ghidra_result,
    _try_decompile_disasm_fallback,
)
from ghidra_shim.envelopes import (  # noqa: F401
    _chunked_envelope,
    _pending_envelope,
)
from ghidra_shim.jobs import (  # noqa: F401
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
from ghidra_shim.listing import (  # noqa: F401
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
from ghidra_shim.logging import _log, _tail_log  # noqa: F401
from ghidra_shim.sessions import (  # noqa: F401
    ALIASES,
    BACKEND,
    BY_PATH,
    LOCKS,
    REG_LOCK,
    SESSIONS,
    STACKS,
    _cleanup,
    _close,
    _ensure_backend,
    _list,
    _open,
    _probe_backend_alive,
    _resolve,
    _sess_payload,
    _teardown_backend,
)
from ghidra_shim.transforms import (  # noqa: F401
    _apply_response_transforms,
    _coerce_none_string_fields,
    _pop_transformer_args,
)

from ghidra_shim.__main__ import main  # noqa: F401


if __name__ == "__main__":
    import anyio

    anyio.run(main)
