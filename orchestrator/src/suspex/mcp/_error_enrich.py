"""Error-message enrichment + typed hint classification.

Every failure envelope in every tool passes through `enrich_error(...)` and
gains a `{kind, hint}` pair alongside the human error string. The hint
strings are the ones a developer needs at the moment the error fires:

    "AttachProcess failed errno_code=1" ->
        {kind: "attach_denied",
         hint: "check debug_manage(action='capabilities'); Session 0 processes need attach via launch(...)"}

The existing `_enrich_win32` (symbol lookup for `gle=87`, `status=0xC0000005`)
composes on top — the enriched message text still comes back with symbolic
names first, then the classifier adds the actionable hint.
"""
from __future__ import annotations

import re

from .error_maps import WIN32_ERRORS


# ---------------------------------------------------------------------------
# Message decoration — extend the existing "gle=N" / "status=0xN" enrichment
# with a small NTSTATUS/HRESULT explainer for the common codes.
# ---------------------------------------------------------------------------

def enrich_win32(msg: str) -> str:
    """Append a symbolic name after any 'gle=N' or 'status=0xN' in msg.

    Same shape the existing `_enrich_win32` in tools.py uses; consolidated
    here so callers importing `_error_enrich` don't need a second import.
    """
    def _sub_dec(m: re.Match[str]) -> str:
        n = int(m.group(1))
        name = WIN32_ERRORS.get(n)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)

    def _sub_hex(m: re.Match[str]) -> str:
        try:
            n = int(m.group(1), 16)
        except ValueError:
            return m.group(0)
        name = WIN32_ERRORS.get(n)
        if name is None and n & 0x80000000 and ((n >> 16) & 0x7FF) == 7:
            # HRESULT_FROM_WIN32: severity=1, facility=7 (11 bits) wraps a
            # Win32 code in the low word (0x80070005 -> ERROR_ACCESS_DENIED).
            name = WIN32_ERRORS.get(n & 0xFFFF)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)

    msg = re.sub(r"gle=(\d+)", _sub_dec, msg)
    msg = re.sub(r"errno_code=(\d+)", _sub_dec, msg)
    msg = re.sub(r"(?:status|nt|err|hr)=0x([0-9a-fA-F]+)", _sub_hex, msg)
    return msg


# ---------------------------------------------------------------------------
# Hint classifier — regex → (kind, hint) pairs.
#
# Order matters: earliest match wins. Put more specific patterns first.
# `kind` should be a stable slug the LLM can branch on programmatically.
# `hint` is a one-line actionable next step in English.
# ---------------------------------------------------------------------------

HINT_RULES: list[tuple[re.Pattern[str], str, str]] = [
    # --- Memory read edge cases ---
    # These come BEFORE the driver-status catch-all: the agent prefixes every
    # driver-side failure with "driver: DeviceIoControl gle=..." — including
    # ones carrying an NTSTATUS marker. Left uncorrected the catch-all wins
    # and INVALID_ADDRESS reads mis-classify as driver_absent_or_stale.
    # v0.16: reordered per the operational-review plan.
    (re.compile(r"gle=299|ERROR_PARTIAL_COPY|STATUS_PARTIAL_COPY|0x8000000D"),
     "partial_read",
     "kernel page not fully resident; retry with allow_fault=true (v6+) or partial=true for a "
     "walk-past-holes read that returns the valid prefix"),

    (re.compile(r"gle=1450|ERROR_NO_SYSTEM_RESOURCES|MmMapIoSpace failed"),
     "phys_map_denied",
     "physical write path is opt-in; mem_rw(action='write', space='physical') requires "
     "allow_map_write=true (v5+); some ranges are still unmappable (HVCI, MMIO holes)"),

    (re.compile(r"STATUS_INVALID_ADDRESS|C0000141"),
     "invalid_address",
     "kernel VA is unmapped or outside a valid range; use mem_rw(action='probe_va') to test "
     "readability without a bugcheck risk, or mem_rw(action='va_translate') to check mapping"),

    # v0.27: the MMIO/BAR class of read failures. A page-table-mapped
    # kernel VA backed by device memory fails MmCopyMemory with an
    # NTSTATUS (STATUS_UNEXPECTED_IO_ERROR / _NETWORK_ERROR /
    # IO_DEVICE_ERROR) whose Win32 projection is gle=59 (or 1117). These
    # arrive through the same "driver: DeviceIoControl gle=..." prefix as
    # a genuinely-absent driver, so this rule must sit BEFORE the driver
    # catch-all or a healthy driver looks missing.
    (re.compile(r"DeviceIoControl gle=(?:59|1117)\b|UNEXP_NET_ERR|"
                r"IO_DEVICE|STATUS_UNEXPECTED_(?:IO|NETWORK)_ERROR|"
                r"0x[Cc]00000[Ee]9|0x[Cc]00000[Cc]4|0x[Cc]0000185"),
     "invalid_address",
     "the read failed at the address itself — this VA is likely backed by "
     "MMIO/device memory that MmCopyMemory won't touch (or is otherwise "
     "I/O-inaccessible). mem_rw(action='va_translate') gives the PA; for "
     "BAR-backed pages read via space='physical' at that PA instead"),

    # --- Driver / device state ---
    (re.compile(r"driver_absent|driver: DeviceIoControl gle=|driver: LastError|"
                r"driver not (?:loaded|present)"),
     "driver_absent_or_stale",
     "run target_manage(action='driver_load') and retry; check target_manage(action='status') "
     "to confirm driver_state == 'loaded'"),

    (re.compile(r"agent < v(\d+)"),
     "agent_version_low",
     "rebuild + redeploy the agent to pick up the newer RPC surface; the current agent "
     "predates this feature"),

    # --- Debugger ---
    (re.compile(r"AttachProcess failed errno_code=1|AttachProcess.*ERROR_INVALID_FUNCTION"),
     "attach_denied",
     "check debug_manage(action='capabilities') to see WHY; common causes: "
     "target is Session 0 / protected process / already being debugged / agent token "
     "missing SeDebugPrivilege"),

    (re.compile(r"CreateProcess2? failed.*hr=0x80070057|E_INVALIDARG.*(?:Create|Launch)"),
     "create_process_e_invalidarg",
     "check exe path (absolute), argument escaping, and working_dir/hidden_window; "
     "for anything that can hang, prefer exec_manage(action='run_detached') over run_exe"),

    (re.compile(r"no active session|E_UNEXPECTED|RPC_S_SERVER"),
     "dbgeng_session_stale",
     "the DbgEng sub-session expired; call debug_manage(action='attach') to re-establish, "
     "or use bp_manage which auto-rebinds on stale-session errors (v0.9+)"),

    # --- Symbols ---
    (re.compile(r"no verified pattern recipe for build \d+|patterns fallback disabled|"
                r"symbols? (?:unavailable|failed)"),
     "no_pattern_for_build",
     "symbol server unavailable for this NT build; check symbols_manage(action='diagnose'), "
     "set SUSPX_SYMBOL_STORE to enable Microsoft symbol server, or supply an offline PDB via "
     "symbols_manage(action='download')"),

    (re.compile(r"PDB.*not (?:found|cached)|dbghelp.*(?:failed|error)"),
     "pdb_missing",
     "PDB not in the local cache and download disabled; run symbols_manage(action='download', "
     "module=...) or set SUSPX_SYMBOL_STORE"),

    # --- Access / permission ---
    (re.compile(r"gle=5\b|ERROR_ACCESS_DENIED|E_ACCESSDENIED|0x80070005"),
     "access_denied",
     "insufficient privilege; verify the agent is running as SYSTEM (or holds SeDebugPrivilege), "
     "and that the driver device SDDL allows this session"),

    (re.compile(r"gle=87\b|ERROR_INVALID_PARAMETER|STATUS_INVALID_PARAMETER"),
     "invalid_parameter",
     "one of the request fields is out of range or the wrong type; re-read the tool's docstring "
     "for the accepted shapes"),

    # --- Network / connect-time classifiers (v0.17 F-1a) ---
    # Placed BEFORE deadline_exceeded / channel_unavailable so the specific
    # OS-level socket errors classify first — otherwise a WSAECONNREFUSED
    # from Session.connect's pre-flight probe (F-1b) mis-classifies as a
    # generic gRPC channel failure and the caller re-probes fruitlessly.
    (re.compile(r"WSAEACCES|10013|permission denied.*socket|EACCES.*connect"),
     "connect_blocked",
     "the OS refused the outbound socket; check firewall rules for the target IP+port. "
     "On Windows, `netsh advfirewall firewall show rule name=all | findstr <port>` may show "
     "a block; the orchestrator may also need admin to bind to a low port"),

    (re.compile(r"WSAETIMEDOUT|10060|ETIMEDOUT|connection timed out"),
     "connect_timeout",
     "TCP SYN reached the host but got no SYN/ACK within the deadline; "
     "confirm the agent is running (`sc.exe query suspex-agent` on the target), the port "
     "is right, and no intermediate firewall/LAN device is silently dropping"),

    (re.compile(r"WSAECONNREFUSED|10061|ECONNREFUSED|connection refused"),
     "connect_refused",
     "host is reachable but nothing is listening on that port; the agent likely stopped — "
     "check `Get-Service suspex-agent` on the target and start it if needed"),

    (re.compile(r"WSAEHOSTUNREACH|10065|EHOSTUNREACH|no route to host"),
     "host_unreachable",
     "no route to the target IP; check ARP, routing, or a downed VPN — "
     "the network stack couldn't even try TCP"),

    (re.compile(r"WSAENETUNREACH|10051|ENETUNREACH|network is unreachable"),
     "network_unreachable",
     "the target network is not reachable from the orchestrator; typically a VPN or NIC issue"),

    # --- Pydantic schema-mismatch intercepts (v0.17 F-2a) ---
    # Kwarg drift bubbles up as raw pydantic error text; without an
    # intercept the caller sees a wall of "1 validation error for … ->
    # extra_forbidden" and no pointer to schemas(...). Fire BEFORE the
    # deadline/channel catch-alls so pydantic frames route here first.
    (re.compile(r"validation error.*for \w+.*extra_forbidden"
                r"|Extra inputs are not permitted"),
     "schema_mismatch",
     "one of the kwargs is not accepted by this tool; check "
     "schemas(tools=['<this_tool>']) for the accepted key list, or run "
     "ida_manage(action='tools') for a one-line inventory"),

    (re.compile(r"validation error.*for \w+.*(?:missing|Field required)"
                r"|Field required.*type=missing"),
     "schema_missing_field",
     "a required kwarg is missing; check schemas(tools=['<this_tool>']) or the "
     "tool's docstring for the required-field list"),

    # --- Bulk table streams (v0.22) ---
    # HandleList on a big table (pid=4 under engine load) used to die as an
    # unclassified stream close; callers fell back to PowerShell. Give it a
    # named kind + the cheap-shape retry recipe BEFORE the generic
    # deadline/channel catch-alls so it doesn't mis-classify.
    (re.compile(r"HandleList.*(?:returned no message|stream close|"
                r"DEADLINE_EXCEEDED|UNAVAILABLE)|"
                r"returned no message.*HandleList"),
     "handles_stream_closed",
     "the handle table RPC died mid-transfer; retry with "
     "summary=true or want_names=false + fields=['handle','type_name','object'] "
     "to shrink the response, or re-poll with limit/offset — the orchestrator "
     "now pages the table internally so a plain retry often succeeds"),

    (re.compile(r"returned no message|stream close mid-call"),
     "agent_stream_closed",
     "the agent's gRPC stream closed before the response landed; retry, or "
     "check target_manage(action='recent_ops') for what was in flight"),

    # --- Deadlines / hangs ---
    (re.compile(r"DEADLINE_EXCEEDED|deadline exceeded|StatusCode\.DEADLINE_EXCEEDED"),
     "deadline_exceeded",
     "call took longer than the client deadline; raise mem_rw(timeout_s=N) for slow reads, or "
     "switch to exec_manage(action='run_detached') for anything that can hang"),

    (re.compile(r"UNAVAILABLE|channel.*(?:closed|shutdown|dead)"),
     "channel_unavailable",
     "gRPC channel to the agent is down; run target_manage(action='status') to re-probe, or "
     "target_manage(action='connect') if the agent restarted"),

    # --- Files / paths ---
    # v14: share-mode-0 lock. gle=32 used to classify as "unknown"; now it's
    # its own kind. Reaching the caller at all means the agent's VSS
    # snapshot fallback already failed (or predates v14).
    (re.compile(r"sharing_locked|gle=32\b|gle=33\b|STATUS_SHARING_VIOLATION|"
                r"0xC0000043|ERROR_LOCK_VIOLATION"),
     "sharing_locked",
     "file is exclusively locked (share-mode 0) — metadata still works; "
     "the agent's VSS snapshot fallback failed too (pre-v14 agent or no "
     "VSS privilege). file_manage(action='follow_start') reports growth "
     "via stat events until the writer releases the lock"),

    (re.compile(r"gle=2\b|ERROR_FILE_NOT_FOUND|0x80070002"),
     "file_not_found",
     "target-side path doesn't exist; run file_manage(action='list_dir', path=...) to verify"),

    (re.compile(r"gle=3\b|ERROR_PATH_NOT_FOUND|0x80070003"),
     "path_not_found",
     "target-side directory doesn't exist along the path; walk with file_manage(action='list_dir')"),

    # --- IDA / bridge ---
    (re.compile(r"ida.*(?:backend|shim).*(?:crashed|dead|not responding)"),
     "ida_backend_dead",
     "the idalib backend crashed; check ida_manage(action='ida_log') for the tail and reopen the "
     "session; large drivers should use open(run_auto_analysis=false) + create_function on the eas of interest"),
]


def classify(msg: str, tool: str = "", action: str = "") -> tuple[str, str]:
    """Return (kind, hint) for the first pattern that matches; ('unknown','')
    when nothing matches.

    v0.17 F-2a: when ``tool`` is provided, ``<this_tool>`` placeholders in
    the matched hint are substituted with the tool name so callers landing
    on a schema_mismatch see the exact schemas(...) invocation to run.
    """
    for pat, kind, hint in HINT_RULES:
        if pat.search(msg):
            if hint and tool and "<this_tool>" in hint:
                hint = hint.replace("<this_tool>", tool)
            return kind, hint
    return "unknown", ""


def enrich_error(tool: str, action: str, msg: str,
                 *, driver_version: str = "") -> dict[str, str]:
    """Full pipeline: enrich the message text, then classify to (kind, hint).

    Returns a dict suitable for spreading into a `{ok: False, ...}` envelope:

        return {"ok": False, **enrich_error(tool, action, str(exc))}

    v0.17 F-2a: pass ``tool`` into ``classify`` so hint templates can
    substitute the tool name.

    v0.17 F-3b: when ``driver_version`` is supplied the "driver < 1.2"
    literal in any classified hint is annotated with the connected
    driver's actual version so the caller sees "you have 1.3 — safe" or
    "you have 1.1 — DANGEROUS" rather than a static warning.
    """
    enriched = enrich_win32(str(msg))
    kind, hint = classify(enriched, tool=tool, action=action)
    if hint and driver_version and "driver < 1.2" in hint:
        try:
            v = tuple(int(x) for x in driver_version.split(".") if x.isdigit())
            if v and v >= (1, 3):
                hint = hint.replace(
                    "driver < 1.2",
                    f"driver < 1.2 (you have {driver_version} — safe)",
                )
            elif v:
                hint = hint.replace(
                    "driver < 1.2",
                    f"driver < 1.2 (you have {driver_version} — DANGEROUS)",
                )
        except (ValueError, AttributeError):
            # Malformed driver_version string; leave the hint alone.
            pass
    out = {"error": enriched, "kind": kind}
    if hint:
        out["hint"] = hint
    # Include tool/action so the LLM can trace which call surfaced this.
    out["tool"] = tool
    out["action"] = action
    return out
