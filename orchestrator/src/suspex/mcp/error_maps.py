"""Shared error-code tables (Win32 + NTSTATUS + HRESULT decomposition)
plus the `KNOWN_KINDS` slug registry (v0.17 F-2b).

Extracted from tools.py so the `_enrich_win32` message decorator and the
`value_manage err_lookup` action (was `type_convert err_lookup` through
v0.17.0) can share one table and stay in sync.
Nothing here is I/O bound — every helper is pure and thread-safe.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# v0.17 F-2b — KNOWN_KINDS registry.
#
# Every ``error.kind`` slug a tool response is allowed to carry lives here.
# Two sources feed the set:
#
# 1. Rule-classified slugs emitted from ``_error_enrich.HINT_RULES`` when a
#    raw failure string matches a known pattern (e.g. ``partial_read``,
#    ``deadline_exceeded``).
# 2. Tool-emitted slugs — dict literals inside ``tools.py`` that build a
#    failure envelope directly (e.g. ``{"kind": "bad_arg", ...}``).
#
# A smoke test in ``orchestrator/tests/test_f_2_schema_mismatch.py`` walks
# ``tools.py`` and asserts every dict-literal ``kind`` string is in this
# set. That keeps a typo like ``"kind": "bad_argment"`` from silently
# shipping and drifting past callers that branch on the slug.
#
# When adding a new slug: register it here, then use it in ``tools.py`` /
# ``HINT_RULES``. Never the other way round.
# ---------------------------------------------------------------------------

KNOWN_KINDS: frozenset[str] = frozenset({
    "unknown",
    "error",  # generic wrapper used by envelope_err

    # ------ From HINT_RULES (rule-classified) ------
    "partial_read", "phys_map_denied", "invalid_address",
    "driver_absent_or_stale", "agent_version_low",
    "attach_denied", "create_process_e_invalidarg", "dbgeng_session_stale",
    "no_pattern_for_build", "pdb_missing",
    "access_denied", "invalid_parameter",
    "deadline_exceeded", "channel_unavailable",
    "file_not_found", "path_not_found",
    "ida_backend_dead",

    # ------ v0.17 new (network layer, F-1a) ------
    "connect_blocked", "connect_timeout", "connect_refused",
    "host_unreachable", "network_unreachable",
    "wait_timeout",

    # ------ v0.17 new (schema, F-2a) ------
    "schema_mismatch", "schema_missing_field",

    # ------ v0.22 new (bulk-table stream failures) ------
    # handle_list on a big table dies as a stream close under load; the
    # generic agent_stream_closed covers every other RPC that resolves to
    # no message mid-call.
    "handles_stream_closed", "agent_stream_closed",

    # ------ v0.17 new (reserved for other workers per _shared.md 0.4) ------
    # Agent B — B-3 (unused kwargs), B-4 (name-collision + zero-match)
    "unknown_kwarg", "kwarg_collision", "filter_no_match",
    # Agent B — B-1 (resolve_symbols=true diagnostics)
    "stale_kaslr", "no_module_at_va",
    # Agent E — E-1 (bare arm collision / foreign-owned watchdog)
    "watchdog_collision",
    # Agent C1 — C1-1 (duplicate name on ida_manage open)
    "session_exists",
    # Agent C2 — C2-3 (cached PDB layout absent)
    "pdb_layout_missing",

    # ------ v0.17 new (probe_va validator, F-3a) ------
    "pte_absent", "kuser_readable", "vad_probed",

    # ------ Tool-emitted (already surfaced in tools.py) ------
    "no_target", "driver_absent", "status_probe_failed",
    # multi-view/no-focus selector ambiguity (session.AmbiguousTargetError;
    # the envelope also carries a `machines` list + a use(...) hint).
    "ambiguous_target",
    "bad_arg", "busy", "confirm_required",
    "read_failed", "write_failed",
    "unsafe_default",  # SUSPEX_MEM_FLAG_ALLOW_SOFTFAULT gate
    "unknown_scan", "not_ready",  # scan_start / scan_status / scan_result
    "foreign_owned",  # ownership refusals (bp/exec/scan/watchdog)
    "artifact_missing",
    "input_too_large",
    # emulate / codegen surface
    "codegen_extra_missing", "engine_init_failed", "unknown_session",
    "no_session", "load_failed", "run_failed", "step_failed",
    "mem_read_failed", "mem_write_failed",
    "map_failed", "unmap_failed",
    "hook_failed", "unknown_hook",
    "not_supported", "snapshot_failed", "no_snapshot", "restore_failed",
    "seed_failed",

    # ------ Tool-emitted (idalib/type introspection) ------
    "struct_not_found", "not_a_udt", "udt_details_unavailable",
    "member_not_found", "type_not_found",

    # ------ v0.17.1 (value_manage eval/constants surface) ------
    "bad_expr", "unsupported_op", "undefined_name",
    "expr_overflow", "division_by_zero", "evaluation_timeout",

    # ------ v0.18 (knowledge_manage surface) ------
    "not_found",         # link() / update() targeting a missing finding_id
    "removed_action",    # deprecated MCP action (generate_report)

    # ------ v0.19 (bin_manage surface) ------
    "bad_magic",          # source buffer isn't a parseable PE
    "module_not_found",   # module= selector matched nothing live
    "enum_failed",        # live module-list enumeration failed
    "func_not_found",     # func=/target= selector matched no function

    # ------ v0.20 (device_manage + threads surface) ------
    "not_allowed",        # actuator refused by config gate (allow_ioctl_send)
    "thread_enum_failed", # system thread enumeration failed on target
    "agent_version",     # target agent predates the RPC (UNIMPLEMENTED)
    # ------ v0.20 (event_manage + obj_enum surface) ------
    "obj_enum_failed",    # kernel object-directory walk failed on target

    # ------ v0.21 (dev-feedback fixes) ------
    "bad_script_b64",    # exec_manage script_b64 payload failed to decode
    "no_module",         # sections= module selector resolved to nothing
    "no_sections",       # sections= names matched no PE section
    "pe_parse",          # live-image PE header read/parse failed

    # ------ v0.22 (symbols_manage surface) ------
    "symbol_not_found",    # SymFromNameW/SymFromAddrW found nothing
    "dbghelp_failed",      # Sym*/dbghelp call itself failed
    "pdb_download_failed", # every configured symbol server failed
    "invalid_layout",      # cached dump_layout JSON malformed/keys absent
    "offset_out_of_range", # resolve_member offset past the struct end

    # ------ v0.23 (bp events / int1 hook surface) ------
    "bp_hook_failed",      # driver refused/failed the IDT[1] install
    "bp_bridge_attach",    # debug-port fallback: dbgeng attach failed
    "bp_bridge_arm",       # debug-port fallback: 'ba' mirror arm failed
    "bp_bridge_multi_pid", # fallback is single-session; bps span pids

    # ------ v0.25 (mem_rw forensic verbs) ------
    "agent_old",           # feature needs a newer agent (hasattr gate)
    "idt_failed",          # IdtList RPC answered but the table walk failed

    # ------ v14 (file locking surface) ------
    "sharing_locked",      # share-mode-0 lock; VSS fallback also failed

    # ------ v15 (exec_manage call) ------
    "bad_target",          # target VA unresolvable / not executable / WOW64
    "call_failed",         # call transport error (non-UNIMPLEMENTED)
    "not_connected",       # require_client(name) found no live view

    # ------ v0.27 (bin_manage async analysis engine) ------
    "analysis_running",    # job accepted; poll bin_manage(job=...)
    "analysis_ready",      # job finished; result payload returned
    "unknown_job",         # analyze_id/job selector matched nothing
    "engine",              # live progress/result payload for a job

    # ------ v0.29 (evidence envelope, Part 3) ------
    "missing_evidence",    # evidence_get/summary/prune: unknown or
                           # malformed evidence_id (never a fs path)

    # ------ v15 (screen_manage) ------
    "screenshot",          # capture: desktop/window PNG + artifact path
    "windows",             # windows: per-process window list + metadata
    "displays",            # displays: monitor topology

    # ------ v0.30 (machine registry) ------
    "machines",            # machines_register/set/unregister/machines

    # ------ v0.31 Phase 1.4 (watchdog refusal) ------
    "watchdog_no_kicker",     # bare arm without a kicker refused by default
    "watchdog_full",          # id=0 auto-allocate: no free slot in 1..64
    "watchdog_list_failed",   # id=0 auto-allocate: watchdog_list() failed
    "watchdog_armed",         # timeline event — currently-armed watchdog row

    # ------ v0.31 Phase 1.5 (mem_rw follow_chain failures) ------
    "bad_offset",             # offsets[i] not parseable
    "hop_read_failed",        # mid-chain deref read raised
    "hop_short_read",         # mid-chain deref returned < 8 bytes
    "terminal_read_failed",   # terminal_size byte read raised
    "expect_ascii_failed",    # terminal bytes failed printable-ASCII check
    "expect_nonzero_failed",  # a hop deref returned 0 while expect_nonzero
    "expect_module_failed",   # terminal VA fell outside the expected module

    # ------ v0.31 Phase 1.6 (timeline) ------
    "boot_identity",          # timeline event — last-seen boot identity
    "boot_notice",            # timeline event — parked boot notice
    "op",                     # timeline event — orchestrator op log row

    # ------ v0.31 Phase 2.4 (rediscover) ------
    "no_candidates",          # rediscover: nothing to probe
})


def is_known_kind(kind: str) -> bool:
    """True when ``kind`` is a documented slug from :data:`KNOWN_KINDS`."""
    return kind in KNOWN_KINDS


# ---------------------------------------------------------------------------
# Common Win32 error codes and NTSTATUS values surfaced by the driver / agent
# as raw "DeviceIoControl gle=87" or "status=0xC0000005" strings. The two
# code spaces never collide numerically (NTSTATUS have 0xC/0x8 top nibble;
# Win32 stay under 32-bit small) so a single lookup by numeric value is safe.
# ---------------------------------------------------------------------------

WIN32_ERRORS: dict[int, str] = {
    # Win32 (from winerror.h). Keep this list conservative — only codes the
    # driver/agent has actually surfaced, so the enrichment stays trustworthy.
    0: "SUCCESS",
    1: "INVALID_FUNCTION",
    2: "FILE_NOT_FOUND",
    3: "PATH_NOT_FOUND",
    5: "ACCESS_DENIED",
    6: "INVALID_HANDLE",
    8: "NOT_ENOUGH_MEMORY",
    13: "INVALID_DATA",
    14: "OUTOFMEMORY",
    18: "NO_MORE_FILES",
    21: "NOT_READY",
    23: "CRC",
    24: "BAD_LENGTH",
    25: "SEEK",
    27: "SECTOR_NOT_FOUND",
    31: "GEN_FAILURE",
    32: "SHARING_VIOLATION",
    33: "LOCK_VIOLATION",
    38: "HANDLE_EOF",
    50: "NOT_SUPPORTED",
    53: "BAD_NETPATH",
    55: "DEV_NOT_EXIST",
    59: "UNEXP_NET_ERR",   # Win32 projection of several device-I/O NTSTATUS
                        # codes (MmCopyMemory on MMIO/BAR pages fails this way)
    64: "NETNAME_DELETED",
    67: "BAD_NET_NAME",
    80: "FILE_EXISTS",
    82: "CANNOT_MAKE",
    87: "INVALID_PARAMETER",
    112: "DISK_FULL",
    122: "INSUFFICIENT_BUFFER",
    123: "INVALID_NAME",
    126: "MOD_NOT_FOUND",
    127: "PROC_NOT_FOUND",
    170: "BUSY",
    183: "ALREADY_EXISTS",
    193: "BAD_EXE_FORMAT",
    234: "MORE_DATA",
    259: "NO_MORE_ITEMS",
    267: "DIRECTORY",
    317: "MR_MID_NOT_FOUND",
    433: "NO_SUCH_DEVICE",
    487: "INVALID_ADDRESS",
    575: "APP_INIT_FAILURE",
    577: "INVALID_IMAGE_HASH",
    633: "SERVICE_NOTIFICATION",
    998: "NOACCESS",
    1114: "DLL_INIT_FAILED",
    1117: "IO_DEVICE",
    1150: "PRODUCT_UNINSTALLED",
    1168: "NOT_FOUND",
    1223: "CANCELLED",
    1275: "DRIVER_BLOCKED",
    1305: "UNKNOWN_REVISION",
    1314: "PRIVILEGE_NOT_HELD",
    1359: "INTERNAL_ERROR",
    1400: "INVALID_WINDOW_HANDLE",
    1450: "NO_SYSTEM_RESOURCES",
    1460: "TIMEOUT",
    1502: "LOG_FILE_FULL",
    1721: "NO_SYSTEM_RESOURCES",
    1722: "RPC_S_SERVER_UNAVAILABLE",
    1726: "RPC_S_CALL_FAILED",
    1727: "RPC_S_CALL_FAILED_DNE",
    1785: "UNRECOGNIZED_MEDIA",
    1816: "NOT_ENOUGH_QUOTA",
    2202: "BAD_USERNAME",
    3221225477: "STATUS_ACCESS_VIOLATION",  # decimal alias for 0xC0000005

    # NTSTATUS (top ~120 the driver/agent are apt to produce). Full list is
    # >1500 entries; keep this focused on codes seen in real IOCTL traffic
    # (memory reads, breakpoints, physical, registry, debugger).
    0x00000000: "STATUS_SUCCESS",
    0x00000080: "STATUS_ABANDONED",
    0x000000C0: "STATUS_USER_APC",
    0x00000101: "STATUS_ALERTED",
    0x00000102: "STATUS_TIMEOUT",
    0x00000103: "STATUS_PENDING",
    0x00000105: "STATUS_MORE_ENTRIES",
    0x00000106: "STATUS_NOT_ALL_ASSIGNED",
    0x00000108: "STATUS_SOME_NOT_MAPPED",
    0x0000010C: "STATUS_NOTIFY_ENUM_DIR",
    0x40000002: "STATUS_WORKING_SET_LIMIT_RANGE",
    0x40000003: "STATUS_IMAGE_NOT_AT_BASE",
    0x40000006: "STATUS_LOCAL_USER_SESSION_KEY",
    0x40000009: "STATUS_BUFFER_OVERFLOW",
    0x40000010: "STATUS_UNMAPPABLE_CHARACTER",
    0x40000015: "STATUS_STOPPED_ON_SYMLINK",
    0x8000000A: "STATUS_HANDLES_CLOSED",
    0x8000000D: "STATUS_PARTIAL_COPY",
    0x8000001A: "STATUS_NO_MORE_ENTRIES",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x80000006: "STATUS_NO_MORE_FILES",
    0x80000021: "STATUS_LONGJUMP",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000003: "STATUS_INVALID_INFO_CLASS",
    0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000006: "STATUS_IN_PAGE_ERROR",
    0xC0000007: "STATUS_PAGEFILE_QUOTA",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000009: "STATUS_BAD_INITIAL_STACK",
    0xC000000A: "STATUS_BAD_INITIAL_PC",
    0xC000000B: "STATUS_INVALID_CID",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000E: "STATUS_NO_SUCH_DEVICE",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xC0000011: "STATUS_END_OF_FILE",
    0xC0000012: "STATUS_WRONG_VOLUME",
    0xC0000013: "STATUS_NO_MEDIA_IN_DEVICE",
    0xC0000015: "STATUS_NONEXISTENT_SECTOR",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000018: "STATUS_CONFLICTING_ADDRESSES",
    0xC0000019: "STATUS_NOT_MAPPED_VIEW",
    0xC000001A: "STATUS_UNABLE_TO_FREE_VM",
    0xC000001B: "STATUS_UNABLE_TO_DELETE_SECTION",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC000001E: "STATUS_INVALID_LOCK_SEQUENCE",
    0xC000001F: "STATUS_INVALID_VIEW_SIZE",
    0xC0000020: "STATUS_INVALID_FILE_FOR_SECTION",
    0xC0000021: "STATUS_ALREADY_COMMITTED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000024: "STATUS_OBJECT_TYPE_MISMATCH",
    0xC0000025: "STATUS_NONCONTINUABLE_EXCEPTION",
    0xC0000026: "STATUS_INVALID_DISPOSITION",
    0xC0000027: "STATUS_UNWIND",
    0xC0000028: "STATUS_BAD_STACK",
    0xC0000029: "STATUS_INVALID_UNWIND_TARGET",
    0xC000002C: "STATUS_STACK_OVERFLOW_READ",
    0xC000002D: "STATUS_INVALID_LOCK_SEQUENCE",
    0xC0000032: "STATUS_DISK_CORRUPT_ERROR",
    0xC0000033: "STATUS_OBJECT_NAME_INVALID",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC0000037: "STATUS_PORT_DISCONNECTED",
    0xC0000039: "STATUS_OBJECT_PATH_INVALID",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC000003B: "STATUS_OBJECT_PATH_SYNTAX_BAD",
    0xC000003C: "STATUS_DATA_OVERRUN",
    0xC000003E: "STATUS_DATA_ERROR",
    0xC0000041: "STATUS_PORT_CONNECTION_REFUSED",
    0xC0000042: "STATUS_INVALID_PORT_HANDLE",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC0000044: "STATUS_QUOTA_EXCEEDED",
    0xC0000045: "STATUS_INVALID_PAGE_PROTECTION",
    0xC0000046: "STATUS_MUTANT_NOT_OWNED",
    0xC0000048: "STATUS_PORT_ALREADY_SET",
    0xC0000049: "STATUS_SECTION_NOT_IMAGE",
    0xC000004A: "STATUS_SUSPEND_COUNT_EXCEEDED",
    0xC000004B: "STATUS_THREAD_IS_TERMINATING",
    0xC000004C: "STATUS_BAD_WORKING_SET_LIMIT",
    0xC000004D: "STATUS_INCOMPATIBLE_FILE_MAP",
    0xC000004E: "STATUS_SECTION_PROTECTION",
    0xC000004F: "STATUS_EAS_NOT_SUPPORTED",
    0xC0000054: "STATUS_FILE_LOCK_CONFLICT",
    0xC0000055: "STATUS_LOCK_NOT_GRANTED",
    0xC0000056: "STATUS_DELETE_PENDING",
    0xC0000058: "STATUS_UNKNOWN_REVISION",
    0xC0000060: "STATUS_SPECIAL_ACCOUNT",
    0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC0000073: "STATUS_NONE_MAPPED",
    0xC0000074: "STATUS_TOO_MANY_LUIDS_REQUESTED",
    0xC0000078: "STATUS_INVALID_ACCOUNT_NAME",
    0xC000007A: "STATUS_PROCEDURE_NOT_FOUND",
    0xC000007B: "STATUS_INVALID_IMAGE_FORMAT",
    0xC000007C: "STATUS_NO_TOKEN",
    0xC000007D: "STATUS_BAD_INHERITANCE_ACL",
    0xC000007E: "STATUS_RANGE_NOT_LOCKED",
    0xC000007F: "STATUS_DISK_FULL",
    0xC0000098: "STATUS_FILE_INVALID",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000A2: "STATUS_MEDIA_WRITE_PROTECTED",
    0xC00000A5: "STATUS_BAD_IMPERSONATION_LEVEL",
    0xC00000AB: "STATUS_INSTANCE_NOT_AVAILABLE",
    0xC00000AC: "STATUS_PIPE_NOT_AVAILABLE",
    0xC00000B0: "STATUS_PIPE_DISCONNECTED",
    0xC00000B1: "STATUS_PIPE_CLOSING",
    0xC00000B5: "STATUS_IO_TIMEOUT",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000C4: "STATUS_UNEXPECTED_NETWORK_ERROR",
    0xC00000D8: "STATUS_CANT_WAIT",
    0xC00000E9: "STATUS_UNEXPECTED_IO_ERROR",
    0xC00000EF: "STATUS_INVALID_PARAMETER_1",
    0xC0000101: "STATUS_DIRECTORY_NOT_EMPTY",
    0xC0000103: "STATUS_NOT_A_DIRECTORY",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000121: "STATUS_CANNOT_DELETE",
    0xC0000122: "STATUS_INVALID_COMPUTER_NAME",
    0xC0000128: "STATUS_FILE_CLOSED",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
    0xC000013A: "STATUS_CONTROL_C_EXIT",
    0xC0000141: "STATUS_INVALID_ADDRESS",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000185: "STATUS_IO_DEVICE_ERROR",
    0xC0000188: "STATUS_LOG_FILE_FULL",
    0xC000018B: "STATUS_NO_TRUST_LSA_SECRET",
    0xC000018D: "STATUS_TRUSTED_DOMAIN_FAILURE",
    0xC0000225: "STATUS_NOT_FOUND",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC0000235: "STATUS_HANDLE_NOT_CLOSABLE",
    0xC000023B: "STATUS_CONNECTION_INVALID",
    0xC0000241: "STATUS_CONNECTION_DISCONNECTED",
    0xC0000243: "STATUS_USER_MAPPED_FILE",
    0xC0000257: "STATUS_PATH_NOT_COVERED",
    0xC000025C: "STATUS_NO_LOGON_SERVERS",
    0xC0000262: "STATUS_DRIVER_ORDINAL_NOT_FOUND",
    0xC0000263: "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND",
    0xC0000264: "STATUS_MUTANT_NOT_OWNED",
    0xC000026E: "STATUS_VOLUME_DISMOUNTED",
    0xC0000275: "STATUS_NOT_A_REPARSE_POINT",
    0xC00002E4: "STATUS_DS_ADMIN_LIMIT_EXCEEDED",
    0xC00002EA: "STATUS_CANNOT_IMPERSONATE",
    0xC0000323: "STATUS_TRANSACTIONAL_CONFLICT",
    0xC0000353: "STATUS_TOO_MANY_LINKS",
    0xC0000388: "STATUS_SXS_KEY_NOT_FOUND",
    0xC0000389: "STATUS_SXS_INVALID_ACTIVATION_CONTEXT_DATA",
    0xC00002C5: "STATUS_DATATYPE_MISALIGNMENT_ERROR",
    0xC0000420: "STATUS_ASSERTION_FAILURE",
    0xC000A200: "STATUS_INVALID_TASK_NAME",
    0xC0140002: "STATUS_SXS_KEY_NOT_FOUND",
}


# HRESULT facility codes (FACILITY_* from winerror.h). Not exhaustive — the
# common ones cover >95% of what the agent will ever see.
HRESULT_FACILITIES: dict[int, str] = {
    0: "NULL", 1: "RPC", 2: "DISPATCH", 3: "STORAGE", 4: "ITF",
    7: "WIN32", 8: "WINDOWS", 9: "SECURITY", 10: "CONTROL", 11: "CERT",
    12: "INTERNET", 13: "MEDIASERVER", 14: "MSMQ", 15: "SETUPAPI",
    16: "SCARD", 17: "COMPLUS", 18: "AAF", 19: "URT", 20: "ACS",
    21: "DPLAY", 22: "UMI", 23: "SXS", 24: "WINDOWS_CE", 25: "HTTP",
    26: "USERMODE_COMMONLOG", 31: "USERMODE_FILTER_MANAGER",
    32: "BACKGROUNDCOPY", 33: "CONFIGURATION", 34: "STATE_MANAGEMENT",
    35: "METADIRECTORY", 36: "WINDOWSUPDATE", 37: "DIRECTORYSERVICE",
    38: "GRAPHICS", 39: "SHELL", 40: "TPM_SERVICES", 41: "TPM_SOFTWARE",
    50: "UI", 51: "XAML", 52: "ACTION_QUEUE", 54: "PLA",
    55: "WINDOWS_SETUP", 56: "FVE", 57: "FWP", 58: "WINRM",
    59: "NDIS", 60: "USERMODE_HYPERVISOR", 61: "CMI",
    62: "USERMODE_VIRTUALIZATION", 63: "USERMODE_VOLMGR",
    64: "BCD", 65: "USERMODE_VHD", 66: "USERMODE_HNS",
    67: "SDIAG", 68: "WEBSERVICES", 69: "WINPE", 70: "WPN",
    71: "WINDOWS_STORE", 72: "INPUT", 73: "EAP", 74: "WINDOWS_DEFENDER",
    75: "OPC", 76: "XPS", 77: "MBN", 78: "POWERSHELL",
    79: "USERMODE_LICENSING", 80: "PORTABLE_DEVICES",
    100: "USER_MODE_HYPERVISOR", 101: "USER_MODE_VIRTUALIZATION",
}


def decode_hresult(value: int) -> dict[str, Any]:
    """Decompose an HRESULT into its severity/facility/code fields.

    HRESULT layout (32-bit):
      bit 31        = severity (0 = success, 1 = failure)
      bits 30..27   = reserved/customer/N-bits (grouped as "flags" here)
      bits 26..16   = facility (11 bits)
      bits 15..0    = code
    """
    v = value & 0xFFFFFFFF
    severity = (v >> 31) & 0x1
    reserved = (v >> 27) & 0xF
    facility = (v >> 16) & 0x7FF
    code = v & 0xFFFF
    return {
        "hex": f"0x{v:08X}",
        "severity": "FAILURE" if severity else "SUCCESS",
        "severity_bit": severity,
        "reserved_bits": reserved,
        "facility": facility,
        "facility_name": HRESULT_FACILITIES.get(facility, "UNKNOWN"),
        "code": code,
        "code_hex": f"0x{code:04X}",
    }


def decode_ntstatus(value: int) -> dict[str, Any]:
    """Decompose an NTSTATUS into its severity/customer/facility/code fields.

    NTSTATUS layout mirrors HRESULT but the severity is 2 bits:
      bits 31..30 = severity (0 success, 1 informational, 2 warning, 3 error)
      bit  29     = customer (Microsoft vs third-party)
      bit  28     = reserved
      bits 27..16 = facility (12 bits)
      bits 15..0  = code
    """
    v = value & 0xFFFFFFFF
    sev = (v >> 30) & 0x3
    customer = (v >> 29) & 0x1
    reserved = (v >> 28) & 0x1
    facility = (v >> 16) & 0xFFF
    code = v & 0xFFFF
    sev_names = {0: "SUCCESS", 1: "INFORMATIONAL", 2: "WARNING", 3: "ERROR"}
    return {
        "hex": f"0x{v:08X}",
        "severity": sev_names[sev],
        "severity_bits": sev,
        "customer": bool(customer),
        "reserved_bit": reserved,
        "facility": facility,
        "code": code,
        "code_hex": f"0x{code:04X}",
        "symbol": WIN32_ERRORS.get(v),
    }


def lookup(value: int, space: str = "auto") -> dict[str, Any]:
    """Resolve an integer to a symbolic name across Win32/NTSTATUS/HRESULT.

    `space` narrows the search:
      "auto"     — Win32 first for small values, NTSTATUS/HRESULT otherwise.
      "win32"    — only the Win32 table.
      "ntstatus" — only NTSTATUS (also runs decode_ntstatus).
      "hresult"  — only HRESULT decomposition (may return symbol too).
    """
    v = value & 0xFFFFFFFF
    out: dict[str, Any] = {"value": v, "hex": f"0x{v:08X}"}
    space = (space or "auto").lower()
    if space == "hresult":
        out["hresult"] = decode_hresult(v)
        out["symbol"] = WIN32_ERRORS.get(v)
        return out
    if space == "ntstatus":
        out["ntstatus"] = decode_ntstatus(v)
        out["symbol"] = WIN32_ERRORS.get(v)
        return out
    if space == "win32":
        out["symbol"] = WIN32_ERRORS.get(v)
        return out
    # auto: try direct lookup, then facility decomposition
    sym = WIN32_ERRORS.get(v)
    if sym is not None:
        out["symbol"] = sym
    # Anything with the top nibble at 0x8 or 0xC is NT-shaped
    if (v >> 28) in (0x8, 0xC):
        out["ntstatus"] = decode_ntstatus(v)
    # Anything with bit 31 set is HRESULT-shaped
    if (v >> 31) & 0x1:
        out["hresult"] = decode_hresult(v)
    return out
