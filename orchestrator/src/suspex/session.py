"""Session state: named target clients per session, grouped by machine.

View keys are ``'<machine>.<kind>'`` — e.g. ``lab2.kernel`` or
``DESKTOP-ABC.user``. The machine label comes from (in priority order) the
``machine=`` connect arg, a config ``machines:`` alias matching the
endpoint, the target's own ``computer_name`` (HostInfo), or the host
address. ``computer_name`` is also stored per view and resolves as an
alias, so a machine stays identifiable when its IP changes.

Per-client ``focus`` (``target_manage(action='use', machine='lab2')``)
fills in the ``name=`` selector when a tool call leaves it empty — each
MCP client has its own focus, so concurrent chats can sit on different
machines without fighting over a global default. With more than one
machine connected, an unfocused empty selector raises
:class:`AmbiguousTargetError` instead of silently hitting whichever box
happened to be primary.

The primary client (the first connected machine's kernel view) keeps the
historical single-target semantics: session.client / session.connected
refer to it."""

from __future__ import annotations

import asyncio
import os
import socket as _socket
import time
from dataclasses import dataclass, field
from typing import Any

from .agent_client import AgentClient, Event
from .allowlist import TargetNotAllowed, check_authorized
from .audit import AuditWriter
from .caller import current_client_id
from .config import PRIMARY_TARGET, SuspexConfig

# Canonical view-kind suffixes in '<machine>.<kind>' view keys.
VIEW_KINDS = ("kernel", "user")


async def _probe_tcp(host: str, port: int, timeout_s: float = 3.0) -> None:
    """Complete a TCP handshake to ``(host, port)`` or raise ``OSError``.

    Runs the blocking connect in the default executor so the caller can
    ``await`` it from an async path. Raises a *rich* ``OSError`` — the
    WSAExxxx / errno tag is embedded in the message so the
    ``_error_enrich.HINT_RULES`` net-layer classifiers (v0.17 F-1a) fire
    correctly and the caller sees ``kind="connect_refused"`` etc. rather
    than the generic ``channel_unavailable`` that gRPC-level failures
    map to.

    The timeout is short (<= 3s by default) — the intent is a pre-flight
    check, not a wait loop. ``target_manage(action='wait_connectable')``
    (F-1c) drives a retry loop on top of this helper.
    """
    loop = asyncio.get_event_loop()

    def _try() -> None:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            s.connect((host, port))

    try:
        await loop.run_in_executor(None, _try)
    except _socket.timeout as exc:
        # ``socket.timeout`` (which is ``TimeoutError`` in 3.10+) is raised
        # by ``settimeout()`` when the OS's TCP stack neither refuses nor
        # completes within the window. Winerror/errno are both None on this
        # path, so tag manually as WSAETIMEDOUT so ``connect_timeout``
        # classifies correctly.
        rich = (f"WSAETIMEDOUT tcp probe to {host}:{port} failed: "
                f"connection timed out after {timeout_s:.1f}s")
        raise OSError(None, rich) from exc
    except OSError as exc:
        # Preserve the original errno/winerror on the raised exception so
        # code that inspects errno still works, while making the *message*
        # rich enough that the regex classifiers in _error_enrich match.
        winerr = getattr(exc, "winerror", None)
        errno_ = getattr(exc, "errno", None)
        # POSIX errno values worth surfacing symbolically so the
        # HINT_RULES fire cross-platform. On Windows winerror wins.
        _POSIX_TAGS = {
            111: "ECONNREFUSED",
            110: "ETIMEDOUT",
            113: "EHOSTUNREACH",
            101: "ENETUNREACH",
            13:  "EACCES",
        }
        if winerr:
            tag = f"WSAE{winerr}"
        elif errno_ in _POSIX_TAGS:
            tag = _POSIX_TAGS[errno_]
        elif errno_:
            tag = f"errno={errno_}"
        else:
            tag = ""
        detail = exc.strerror or str(exc)
        # Attach the resolved endpoint for triage without leaking auth data.
        rich = f"{tag} tcp probe to {host}:{port} failed: {detail}".strip()
        raise OSError(exc.errno, rich) from exc


class AmbiguousTargetError(RuntimeError):
    """A tool call left ``name=`` empty (or used a bare view kind) while
    more than one machine is connected and the caller holds no focus.

    Carries the live machine list so the error envelope can name the
    options; the hint points at ``target_manage(action='use')``.
    """

    kind = "ambiguous_target"

    def __init__(self, machines: list[str]):
        self.machines = list(machines)
        super().__init__(
            "ambiguous target: " + (", ".join(self.machines) or "<none>")
            + " connected — pick one with "
              "target_manage(action='use', machine='<name>') "
              "or pass name='<machine>.kernel' explicitly")
        self.hint = ("target_manage(action='use', machine=...) sets your "
                     "chat's current machine; name='<machine>.kernel|user' "
                     "selects a view explicitly")


@dataclass
class ToolCall:
    tool: str
    action: str
    destructive: bool
    args: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: str = ""
    ts: float = field(default_factory=time.time)


DESTRUCTIVE_ACTIONS = {
    ("target_manage", "driver_unload"),
    ("target_manage", "driver_load"),
    ("target_manage", "disconnect"),
    ("file_manage", "delete"),
    ("exec_manage", "kill_process"),
    ("exec_manage", "stop_shell"),
    ("exec_manage", "suspend"),
    # v15: exec_manage call — remote function execution (remote thread /
    # kernel work item). Gated by security.allow_function_call as well.
    ("exec_manage", "call"),
    ("debug_manage", "detach"),
    ("mem_rw", "free"),
    ("bp_manage", "remove"),
    ("script_manage", "run"),
    # v11: event subscribe registers PsSet*NotifyRoutine callbacks —
    # kernel-visible state, gated like driver_load.
    ("event_manage", "subscribe"),
}


class Session:
    def __init__(self, cfg: SuspexConfig) -> None:
        self.cfg = cfg
        self.clients: dict[str, AgentClient] = {}
        # Per-name primary owner (first connector, or the caller that forced
        # a takeover) and per-name refcounts by owner id. A named entry is
        # torn down only when every owner has released it (refs empties).
        self.owners: dict[str, str] = {}
        self.refs: dict[str, dict[str, int]] = {}
        self.primary = PRIMARY_TARGET
        # view key -> {"machine", "computer_name", "endpoint"}. Written at
        # connect after the HostInfo round-trip; kept after disconnect so
        # `targets` can still name the boxes it lists as not_connected.
        self._machine_info: dict[str, dict[str, Any]] = {}
        # client_id -> {"machine", "kind"} set by target_manage(action='use').
        # Per-caller "current machine" — fills empty/bare `name=` selectors
        # so a chat's calls land on its own box, never a global default.
        self._focus: dict[str, dict[str, str]] = {}
        self.tool_log: list[ToolCall] = []
        # v0.17 E-2b: persistent audit sink. Deterministic per orchestrator
        # boot (PID + start epoch) so concurrent instances on the same host
        # don't clobber each other's roll files. The writer resolves the
        # base via `audit.default_base()` — which honors
        # `SUSPX_AUDIT_BASE_DIR` — so tests can point both write and query
        # paths at a tmp_path with a single env var.
        self._audit_session_id = f"orch-{os.getpid()}-{int(time.time())}"
        self._audit = AuditWriter(session_id=self._audit_session_id)
        # v14: last-seen boot identity per view — (boot_epoch_ms,
        # agent_instance_id) from the newest StatusResponse. A changed boot
        # epoch means the target rebooted (driver state, shells, follows,
        # watchdogs, detached handles all orphaned); a changed instance id
        # on the same boot means the agent process restarted.
        self._boot_ids: dict[str, dict[str, Any]] = {}
        # v0.25: boot monitor. A per-view background task polls status()
        # and feeds every reply through note_boot_identity, making
        # reboot/agent-restart detection timely instead of lazy. The
        # change record the monitor produced is parked in
        # pending_boot_notices so the next status()/wait_boot_change call
        # still surfaces it to the caller (drain-and-clear).
        self.pending_boot_notices: dict[str, dict[str, Any]] = {}
        self._boot_monitors: dict[str, asyncio.Task] = {}
        # Minidump dir-watch seen-set per view — names already reported
        # (or seeded on first scan) so each new .dmp notifies once.
        self._dump_seen: dict[str, set[str]] = {}
        # v0.28: last host that actually connected, per machine label —
        # retried first when the configured endpoint fails the pre-flight
        # probe (NIC lease flap, DHCP change).
        self._last_good_host: dict[str, str] = {}

    def note_boot_identity(self, name: str, status: dict[str, Any]) -> dict[str, Any] | None:
        """Compare ``status``'s boot identity against the last seen for view
        ``name``. Returns a change record when the far end came back
        different (``kind`` = ``new_boot`` or ``agent_restart``), else None.
        Pre-v14 agents report neither field and are treated as
        indeterminate — recorded only when present, never flagged."""
        boot = int(status.get("boot_epoch_ms") or 0)
        inst = str(status.get("agent_instance_id") or "")
        if not boot and not inst:
            return None
        prev = self._boot_ids.get(name)
        self._boot_ids[name] = {"boot_epoch_ms": boot, "agent_instance_id": inst}
        if prev is None:
            return None
        if boot and prev.get("boot_epoch_ms") != boot:
            return {"kind": "new_boot", "view": name,
                    "prev_boot_epoch_ms": prev.get("boot_epoch_ms"),
                    "boot_epoch_ms": boot,
                    "agent_instance_id": inst}
        if inst and prev.get("agent_instance_id") and \
                prev.get("agent_instance_id") != inst:
            return {"kind": "agent_restart", "view": name,
                    "boot_epoch_ms": boot,
                    "agent_instance_id": inst}
        return None

    def boot_identity(self, name: str) -> dict[str, Any]:
        """Last boot identity recorded for view ``name`` by
        note_boot_identity — ``{}`` when the view has never answered a
        status carrying boot fields."""
        return dict(self._boot_ids.get(name) or {})

    def start_boot_monitor(self, name: str, interval_s: float = 5.0, *,
                           on_change=None, on_scan=None,
                           scan_idle_s: float = 60.0) -> bool:
        """Spawn (idempotently) the per-view boot-change poller.

        Every ``interval_s`` the loop calls ``client.status()`` for the
        named view and pushes the reply through
        :meth:`note_boot_identity` — the same detector ``status()`` uses,
        just timely rather than lazy. A change record is parked in
        ``pending_boot_notices`` (drained by the next status call) and
        ``on_change(name, change)`` runs for orchestrator-side followup
        (state sweep, auto minidump pull). While the view stays quiet
        for ``scan_idle_s`` straight, ``on_scan(name, boot_epoch_ms)``
        fires for lazy work that would be too expensive every tick (the
        minidump-dir watch).

        ``interval_s <= 0`` is the explicit disable; returns False and
        spawns nothing. Idempotent — a live monitor is never replaced.
        """
        if interval_s <= 0:
            return False
        existing = self._boot_monitors.get(name)
        if existing is not None and not existing.done():
            return False
        self._boot_monitors[name] = asyncio.create_task(
            self._boot_monitor_loop(
                name, float(interval_s), on_change=on_change,
                on_scan=on_scan, scan_idle_s=float(scan_idle_s)),
            name=f"suspex-bootmon-{name}")
        return True

    def stop_boot_monitor(self, name: str | None = None) -> None:
        """Cancel monitor task(s); ``name=None`` stops every view's."""
        for n, task in list(self._boot_monitors.items()):
            if name is None or n == name:
                task.cancel()
                self._boot_monitors.pop(n, None)

    def boot_monitor_running(self, name: str) -> bool:
        task = self._boot_monitors.get(name)
        return task is not None and not task.done()

    async def _boot_monitor_loop(self, name: str, interval_s: float, *,
                                 on_change, on_scan,
                                 scan_idle_s: float) -> None:
        last_scan = time.monotonic()
        while True:
            await asyncio.sleep(interval_s)
            client = self.clients.get(name)
            if client is None:
                continue
            try:
                st = await client.status()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — transient poll failures are silent
                continue
            change = self.note_boot_identity(name, st)
            now = time.monotonic()
            if change is not None:
                last_scan = now
                change.setdefault("source", "boot_monitor")
                self.pending_boot_notices[name] = change
                if on_change is not None:
                    try:
                        await on_change(name, change)
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001 — monitor work is best-effort
                        pass
            elif on_scan is not None and (now - last_scan) >= scan_idle_s:
                last_scan = now
                try:
                    await on_scan(name, int(st.get("boot_epoch_ms") or 0))
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    pass

    def audit_session_id(self) -> str:
        """The audit sink's session_id (used by target_manage
        recent_ops(persistent=True) so the query targets the current
        orchestrator's own JSONL tree)."""
        return self._audit_session_id

    @property
    def client(self) -> AgentClient | None:
        return self.clients.get(self.primary)

    @property
    def connected(self) -> bool:
        return bool(self.clients)

    def check_target(self, host: str | None = None) -> str:
        host = host or self.cfg.target.host
        return check_authorized(host, self.cfg.security.authorized_targets)

    def _connect_plan(self, name: str, machine: str | None,
                      host: str | None, port: int | None,
                      token: str | None) -> tuple[str | None, str, "Any"]:
        """Resolve connect args to ``(machine_label_or_None, view_kind,
        TargetConfig)``.

        ``machine='lab2'`` names the box; ``name='lab2.user'`` picks the
        view kind explicitly; bare view kinds ('kernel'/'user') leave the
        label to be learned post-connect (computer_name > config alias >
        host). Other bare names are machine aliases and imply the kernel
        view — ``connect(name='lab2')`` == ``connect(machine='lab2')``.

        Endpoint resolution never crosses machines: with an explicit label
        the endpoint must come from a machine-scoped config entry
        (``machines.lab2`` / ``targets['lab2.kernel']``), a sibling view's
        host (kind-port convention applies), or explicit host=/port= —
        falling back to the default ``target`` endpoint for a named other
        machine is exactly the wrong-machine bug this exists to prevent.
        """
        from .config import TargetConfig
        requested = (name or "").strip()
        kind = requested.lower() if requested.lower() in VIEW_KINDS else PRIMARY_TARGET
        if machine:
            label: str | None = machine
            if "." in requested:
                kind = requested.rsplit(".", 1)[1]
        elif "." in requested:
            label, kind = requested.rsplit(".", 1)
        elif requested and requested.lower() not in VIEW_KINDS:
            label = requested
        else:
            label = None

        t = None
        if label is not None:
            for cand in (f"{label}.{kind}", label):
                try:
                    t = self.cfg.target_for(cand)
                    break
                except KeyError:
                    continue
            if t is None:
                # Same-machine sibling views share a host; the kind's
                # conventional port (50099 kernel / 50075 user) applies
                # unless the caller passes port= explicitly.
                sib_host = ""
                for key, c in self.clients.items():
                    if self.machine_of(key) == label:
                        sib_host = (getattr(c, "endpoint", "") or "") \
                            .rsplit(":", 1)[0]
                        break
                eff_host = host or sib_host
                eff_port = port or (50099 if kind == "kernel" else 50075)
                if eff_host:
                    t = TargetConfig(host=eff_host, port=int(eff_port),
                                     token=token or "")
            if t is None:
                raise KeyError(
                    f"no endpoint known for {label}.{kind} — configure "
                    f"machines.{label} in the config or pass host=/port=")
            return label, kind, t
        for cand in (requested, kind):
            try:
                t = self.cfg.target_for(cand)
                break
            except KeyError:
                continue
        if t is None:
            if not host or not port:
                raise KeyError(
                    f"unknown or incomplete endpoint "
                    f"{requested or kind!r} — pass both host= and port= "
                    "or add it to machines:/targets: in the config")
            t = TargetConfig(host=host, port=int(port), token=token or "")
        return label, kind, t

    async def connect(self, host: str | None = None, port: int | None = None,
                      token: str | None = None, name: str = PRIMARY_TARGET,
                      machine: str | None = None,
                      owner: str | None = None, force: bool = False) -> dict[str, Any]:
        """Connect (or attach to an already-connected) named view.

        Sharing semantics:
        - First connector becomes ``primary_owner``; refcount for that owner
          starts at 1.
        - A later connect(owner=same) simply bumps that owner's refcount and
          returns the live client's status with ``shared`` set when other
          owners are also attached.
        - A later connect(owner=different, force=False) attaches the new
          owner as a co-owner (refs[owner]=1); ``shared`` will be True.
        - force=True under a different owner tears the view down and
          rebuilds it (``forced_takeover=True`` in the envelope).

        The stored view key is ``'<machine>.<kind>'``. When the machine
        label can't be derived from the args it is learned post-connect
        (computer_name > config alias > host). If that key is already
        connected — e.g. connect(name='kernel') landing on an existing
        'DESKTOP-ABC.kernel' — the fresh channel is closed and the call
        attaches to the existing view instead of duplicating it.
        """
        label, kind, t = self._connect_plan(name, machine, host, port, token)
        host = host or t.host
        port = port or t.port
        token = token if token is not None else t.token
        # v0.28: endpoint candidates — configured/explicit host first,
        # then the last host that actually connected for this machine
        # (NIC lease flap: DHCP moved the box to the other lease), then
        # the configured alt_hosts. Allowlist violations still abort
        # immediately; only network-level probe failures fall through.
        candidates: list[str] = []
        for h in (host, self._last_good_host.get(label or "", ""),
                  *(getattr(t, "alt_hosts", None) or [])):
            if h and h not in candidates:
                candidates.append(h)
        for cand in candidates:
            self.check_target(cand)
        probe_timeout_s = min(3.0, (t.connect_timeout_ms or 3000) / 1000.0)
        tried: list[str] = []
        probe_err: Exception | None = None
        for cand in candidates:
            tried.append(cand)
            try:
                await _probe_tcp(cand, port, timeout_s=probe_timeout_s)
                host = cand
                probe_err = None
                break
            except OSError as exc:
                probe_err = exc
        if probe_err is not None:
            raise probe_err
        self._last_good_host[label or ""] = host
        if len(candidates) > 1:
            endpoint_fallback = {
                "configured": candidates[0],
                "tried": tried,
                "used": host,
            }
        else:
            endpoint_fallback = None
        self.check_target(host)
        owner_id = owner or "anonymous"
        planned = f"{label}.{kind}" if label else None
        existing = self.clients.get(planned) if planned else None
        forced = False
        if existing is not None:
            primary_owner = self.owners.get(planned, owner_id)
            refs = self.refs.setdefault(planned, {})
            same_owner = (primary_owner == owner_id) or (owner is None)
            if force and not same_owner:
                # Tear down the existing session; a fresh entry is built
                # below owned by the forcing caller.
                await existing.close()
                self.clients.pop(planned, None)
                self.owners.pop(planned, None)
                self.refs.pop(planned, None)
                self.stop_boot_monitor(planned)
                forced = True
            else:
                # Either same owner (increment) or different owner without
                # force (add as co-owner). Either way, bump the counter and
                # hand back the live client's status.
                refs[owner_id] = refs.get(owner_id, 0) + 1
                status = await existing.status()
                status["shared"] = len(refs) > 1
                status["primary_owner"] = primary_owner
                status["view"] = planned
                status["machine"] = self.machine_label(planned)["machine"]
                change = self.note_boot_identity(planned, status)
                if change:
                    status["boot_change"] = change
                return status
        # v0.17 F-1b: pre-flight TCP probe. gRPC's `channel_ready()` wraps
        # OS-level socket errors in an opaque UNAVAILABLE StatusCode, so a
        # WSAECONNREFUSED / WSAETIMEDOUT bubbles up as a generic
        # "channel_unavailable" hint. Doing a plain socket connect first
        # surfaces the OS error rich enough for the net-layer classifiers
        # (`connect_blocked` / `connect_timeout` / `connect_refused` /
        # `host_unreachable` / `network_unreachable`) to fire, so the
        # caller gets an actionable next step instead of "channel is down".
        # (The probe ran above across the endpoint candidates; only the
        # degenerate empty-candidate case probes here.)
        if not candidates:
            await _probe_tcp(host, port, timeout_s=probe_timeout_s)
        client = AgentClient(host, port, token, t.connect_timeout_ms,
                             max_inflight=t.max_inflight)
        await client.connect()
        status = await client.status()
        if endpoint_fallback:
            status["endpoint_fallback"] = endpoint_fallback
        # Machine identity: learn computer_name now (best-effort) so the
        # view key can carry it and later responses can self-label.
        computer_name = ""
        try:
            hi = await client.host_info(include_hardware=False,
                                        include_security_products=False)
            if hi.get("ok"):
                computer_name = str(
                    (hi.get("identity") or {}).get("computer_name") or "")
        except Exception:  # noqa: BLE001 — host_info is agent-version dependent
            pass
        if label is None:
            label = (self.cfg.machine_for_endpoint(host, port)
                     or computer_name or self._label_for_host(host) or host)
        key = f"{label}.{kind}"
        existing = self.clients.get(key)
        if existing is not None and existing is not client:
            # Another channel already serves this view (label learned
            # post-connect) — same owner/force semantics as the planned-
            # key path above: force under a different owner tears it down,
            # otherwise attach rather than keep a duplicate channel.
            primary_owner = self.owners.get(key, owner_id)
            same_owner = (primary_owner == owner_id) or (owner is None)
            if force and not same_owner:
                # The fresh channel becomes the replacement; tear down
                # the old one and fall through to the rebuild below.
                await existing.close()
                self.clients.pop(key, None)
                self.owners.pop(key, None)
                self.refs.pop(key, None)
                self.stop_boot_monitor(key)
                forced = True
            else:
                await client.close()
                refs = self.refs.setdefault(key, {})
                refs[owner_id] = refs.get(owner_id, 0) + 1
                status = await existing.status()
                status["shared"] = len(refs) > 1
                status["primary_owner"] = self.owners.get(key, owner_id)
                status["view"] = key
                status["machine"] = self.machine_label(key)["machine"]
                return status
        self.clients[key] = client
        self.owners[key] = owner_id
        self.refs[key] = {owner_id: 1}
        self.note_machine_identity(key, computer_name=computer_name,
                                   endpoint=f"{host}:{port}")
        if forced:
            status["forced_takeover"] = True
        status["shared"] = False
        status["primary_owner"] = owner_id
        status["view"] = key
        status["machine"] = label
        if computer_name:
            status["computer_name"] = computer_name
        if self.primary not in self.clients:
            self.primary = key
        # First connect auto-focuses the caller on this machine when they
        # hold no focus yet — "the box I just connected to" is the least
        # surprising default. An existing focus is never moved silently.
        if owner and owner not in self._focus:
            self._focus[owner] = {"machine": label, "kind": kind}
        # v14: a forced/fresh connect after a reboot still carries the old
        # view's boot record — flag the epoch change so callers know prior
        # shells/follows/handles were orphaned even though the channel is
        # brand new.
        change = self.note_boot_identity(key, status)
        if change:
            status["boot_change"] = change
        return status

    def drop_view_ref(self, name: str, owner: str) -> bool:
        """v0.24: remove one owner's ref on a named view WITHOUT closing the
        client. driver_unload uses this to prune refs the ClientRegistry
        says are stale (crashed peer, release_peer leftover) so the
        session-ledger and the peer dashboard stop disagreeing. Returns
        True when a ref was actually dropped."""
        refs = self.refs.get(name)
        if not refs or owner not in refs:
            return False
        refs[owner] -= 1
        if refs[owner] <= 0:
            refs.pop(owner, None)
        return True

    async def disconnect(self, name: str | None = None,
                         owner: str | None = None) -> dict[str, Any]:
        """Release a named target.

        - ``owner=None`` preserves the historical all-close behavior used by
          the process-shutdown path: every named client is closed and its
          ref bookkeeping cleared.
        - ``owner`` given: decrement that owner's refcount on the named
          entry (or every entry when ``name`` is None). The underlying
          client is only closed when every owner has released it.

        Returns ``disconnected`` (names actually torn down) and, when
        owner-scoped, ``partial_release`` (names whose refcount merely
        decremented).
        """
        if owner is None:
            names = [name] if name else list(self.clients)
            for n in names:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                if client is not None:
                    await client.close()
            self._repoint_primary()
            return {"ok": True, "disconnected": names}
        targets = [name] if name else list(self.clients)
        closed: list[str] = []
        partial: list[str] = []
        for n in targets:
            refs = self.refs.get(n)
            if refs is None:
                continue
            if owner in refs:
                refs[owner] -= 1
                if refs[owner] <= 0:
                    refs.pop(owner, None)
            if not refs:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                if client is not None:
                    await client.close()
                closed.append(n)
            else:
                partial.append(n)
        self._repoint_primary()
        return {"ok": True, "disconnected": closed, "partial_release": partial}

    def _repoint_primary(self) -> None:
        """Keep ``self.primary`` pointing at a live view — prefer a
        '<machine>.kernel' key, else the alphabetically-first view."""
        if self.primary in self.clients:
            return
        for key in sorted(self.clients):
            if self.view_kind_of(key) == PRIMARY_TARGET:
                self.primary = key
                return
        self.primary = next(iter(sorted(self.clients)), PRIMARY_TARGET)

    async def release_by_owner(self, owner: str) -> list[str]:
        """Drop every reference held by ``owner`` and close any entry whose
        refcount thereby reaches zero. Intended for the client-reap path
        when a caller disappears; returns the list of names actually closed.
        The caller is responsible for publishing / logging as needed.
        """
        released: list[str] = []
        self._focus.pop(owner, None)
        for n in list(self.clients):
            refs = self.refs.get(n)
            if refs is None or owner not in refs:
                continue
            refs.pop(owner, None)
            if not refs:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                if client is not None:
                    await client.close()
                released.append(n)
        self._repoint_primary()
        return released

    # ------------------------------------------------------------ machines ----

    @staticmethod
    def machine_of(view_name: str) -> str:
        """Machine label out of a ``'<machine>.<kind>'`` view key. Undotted
        keys are their own machine label (raw-name connects)."""
        return view_name.rsplit(".", 1)[0] if "." in view_name else view_name

    @staticmethod
    def view_kind_of(view_name: str) -> str:
        """View-kind suffix of a ``'<machine>.<kind>'`` key ('kernel',
        'user', ...). Undotted keys return the whole name."""
        return view_name.rsplit(".", 1)[1] if "." in view_name else view_name

    def machines(self) -> dict[str, list[str]]:
        """Connected machine label -> sorted view keys, ordered by first
        connect."""
        out: dict[str, list[str]] = {}
        for key in self.clients:
            out.setdefault(self.machine_of(key), []).append(key)
        for views in out.values():
            views.sort()
        return out

    def machine_label(self, view_name: str) -> dict[str, Any]:
        """Identity record for a view's machine: {machine, computer_name,
        endpoint}. Falls back to the key prefix when HostInfo never ran."""
        info = self._machine_info.get(view_name) or {}
        client = self.clients.get(view_name)
        endpoint = getattr(client, "endpoint", "") or info.get("endpoint", "")
        cn = info.get("computer_name") or ""
        if not cn:
            # A view without its own identity (umagent) inherits the
            # computer_name a sibling view on the same machine learned.
            m = self.machine_of(view_name)
            for k, v in self._machine_info.items():
                if self.machine_of(k) == m and v.get("computer_name"):
                    cn = v["computer_name"]
                    break
        return {"machine": info.get("machine") or self.machine_of(view_name),
                "computer_name": cn,
                "endpoint": endpoint}

    def _label_for_host(self, host: str) -> str:
        """Machine label already connected on *host* — the sibling view's
        machine. The umagent doesn't report computer_name, so 'same box'
        is 'same agent host'; this keeps one machine per physical box."""
        for key, c in self.clients.items():
            ep = getattr(c, "endpoint", "") or ""
            if ep.rsplit(":", 1)[0] == host:
                return self.machine_of(key)
        return ""

    def note_machine_identity(self, view_name: str, *,
                              computer_name: str = "",
                              endpoint: str = "") -> None:
        """Cache machine identity for a view key (called after host_info)."""
        info = self._machine_info.setdefault(view_name, {})
        info["machine"] = self.machine_of(view_name)
        if computer_name:
            info["computer_name"] = computer_name
        if endpoint:
            info["endpoint"] = endpoint

    def _machine_candidates(self) -> dict[str, str]:
        """case-insensitive alias -> canonical machine label. Aliases are
        the connected key prefix, the cached computer_name, and config
        ``machines:``/dotted-``targets:`` names."""
        cand: dict[str, str] = {}
        for key in self.clients:
            m = self.machine_of(key)
            cand.setdefault(m.lower(), m)
            cn = (self._machine_info.get(key) or {}).get("computer_name")
            if cn:
                cand.setdefault(str(cn).lower(), m)
        for cfg_name in getattr(self.cfg, "machines", {}) or {}:
            cand.setdefault(cfg_name.lower(), cfg_name)
        for cfg_name in getattr(self.cfg, "targets", {}) or {}:
            if "." in cfg_name:
                cand.setdefault(
                    self.machine_of(cfg_name).lower(), self.machine_of(cfg_name))
        return cand

    def _match_machine(self, token: str) -> str | None:
        """Resolve a machine token (label / computer_name / config alias)
        to a canonical machine label, or None."""
        if not token:
            return None
        return self._machine_candidates().get(token.lower())

    def _default_view_for_machine(self, machine: str) -> str:
        """The view a bare selector on *machine* should hit: its kernel
        view when connected, else the alphabetically-first live view, else
        the canonical kernel key (so the error message names it)."""
        kernel_key = f"{machine}.{PRIMARY_TARGET}"
        if kernel_key in self.clients:
            return kernel_key
        for key in sorted(self.clients):
            if self.machine_of(key) == machine:
                return key
        return kernel_key

    def _view_for(self, machine: str, kind: str) -> str:
        """The connected view key for machine+kind; falls back to the
        canonical '<machine>.<kind>' spelling so callers can report it."""
        want = kind.lower()
        for key in self.clients:
            if self.machine_of(key) == machine and \
                    self.view_kind_of(key).lower() == want:
                return key
        return f"{machine}.{kind}"

    # -------------------------------------------------------------- focus ----

    def set_focus(self, client_id: str, selector: str) -> dict[str, Any]:
        """Bind *client_id* to a machine (or machine.kind). Raises
        RuntimeError when the selector matches no connected machine —
        focus must point at something live."""
        machine_token, _, kind = (selector or "").partition(".")
        machine = self._match_machine(machine_token)
        if machine is None:
            raise RuntimeError(
                f"use: unknown machine {machine_token!r} — connected "
                f"machines: {', '.join(sorted(self.machines())) or '<none>'}; "
                "connect first with target_manage(action='connect', "
                "machine=...)")
        if kind and kind.lower() not in [k.lower() for k in VIEW_KINDS] and \
                self._view_for(machine, kind) not in self.clients:
            raise RuntimeError(
                f"use: machine {machine!r} has no view kind {kind!r} "
                f"(has: {self.machines().get(machine)})")
        self._focus[client_id] = {"machine": machine,
                                  "kind": kind.lower() or PRIMARY_TARGET}
        return {"machine": machine, "kind": kind.lower() or PRIMARY_TARGET,
                "view": self._view_for(machine, kind.lower() or PRIMARY_TARGET),
                **self.machine_label(
                    self._view_for(machine, kind.lower() or PRIMARY_TARGET))}

    def clear_focus(self, client_id: str) -> bool:
        return self._focus.pop(client_id, None) is not None

    def focus_of(self, client_id: str) -> dict[str, str] | None:
        f = self._focus.get(client_id)
        return dict(f) if f else None

    def _default_machine(self, client_id: str | None) -> str | None:
        """Which machine an empty selector lands on for *client_id*:
        their focus, the only connected machine, or AmbiguousTargetError."""
        cid = client_id or current_client_id()
        f = self._focus.get(cid)
        if f is not None:
            return f["machine"]
        machines = self.machines()
        if len(machines) == 1:
            return next(iter(machines))
        if not machines:
            return None
        raise AmbiguousTargetError(sorted(machines))

    def resolve_view_name(self, name: str = "",
                          client_id: str | None = None) -> str:
        """Map a caller's ``name=`` selector to a concrete view key.

        Accepted shapes:
          ''              -> focus machine's focus kind, the only connected
                           machine's kernel view, or AmbiguousTargetError
          '<m>.<kind>'    -> that view (machine matched against label /
                           computer_name / config alias, case-insensitive)
          '<machine>'     -> the machine's kernel view
          '<kind>'        -> that view kind on the caller's focus machine
                           (or the only machine)
          anything else   -> returned verbatim; require_client reports it
                           as not-connected.
        """
        name = (name or "").strip()
        if name in self.clients:
            return name
        if "." in name:
            m_tok, kind = name.rsplit(".", 1)
            machine = self._match_machine(m_tok)
            if machine is None:
                raise RuntimeError(
                    f"unknown machine {m_tok!r} — connected machines: "
                    f"{', '.join(sorted(self.machines())) or '<none>'}")
            key = self._view_for(machine, kind)
            if key not in self.clients:
                views = self.machines().get(machine) or []
                raise RuntimeError(
                    f"view {name!r} not connected — machine {machine!r} "
                    f"has views: {views or '<none>'}")
            return key
        if name:
            machine = self._match_machine(name)
            if machine is not None:
                return self._default_view_for_machine(machine)
            if name.lower() in VIEW_KINDS:
                machine = self._default_machine(client_id)
                if machine is None:
                    return name
                return self._view_for(machine, name.lower())
            return name
        machine = self._default_machine(client_id)
        if machine is None:
            return self.primary
        f = self._focus.get(client_id or current_client_id()) or {}
        return self._view_for(machine, f.get("kind") or PRIMARY_TARGET)

    def target_stamp(self, name: str = "") -> dict[str, Any] | None:
        """Best-effort {view, machine, computer_name, endpoint} block for
        envelope stamping â€” never raises; None when nothing resolves."""
        try:
            key = self.resolve_view_name(name)
        except Exception:
            return None
        if key not in self.clients:
            return None
        return {"view": key, **self.machine_label(key)}

    def stamp_needed(self, view_key: str) -> bool:
        """v0.30 minimal-envelope stamp policy: responses carry a bare
        ``target: '<machine>.<kind>'`` view key only when the answer could
        be attributed to the wrong box â€” more than one view is connected,
        or the view isn't the caller's focus machine. Single-view sessions
        cost zero stamp context. Full machine identity (trust/purpose/
        endpoints) is delivered once per machine on first connect
        (machine_info) and on demand via target_manage(action='machines')."""
        if len(self.clients) > 1:
            return True
        f = self._focus.get(current_client_id())
        if not f:
            return False
        return (f.get("machine") or "") != self.machine_of(view_key)

    def require_client(self, name: str = "") -> AgentClient:
        n = self.resolve_view_name(name)
        client = self.clients.get(n)
        if client is None:
            raise RuntimeError(
                f"not connected: target {n!r} — call target_manage(action='connect', name={n!r}) first")
        return client

    def all_views(self) -> list[dict[str, Any]]:
        """Every configured target view (kernel, user, ...) with connection
        state + last-seen timestamps. Used by target_manage(action='targets')
        to make post-reboot reconnect deterministic — configured endpoints
        + last-seen tell the caller which view to reconnect and where.
        """
        import datetime as _dt
        rows: list[dict[str, Any]] = []
        # Every view mentioned in config plus any dynamically-connected view.
        cfg_names: set[str] = set()
        for name in getattr(self.cfg, "targets", {}):
            cfg_names.add(name)
        for mname, mcfg in (getattr(self.cfg, "machines", {}) or {}).items():
            views = getattr(mcfg, "views", {}) or {}
            for kind in views or ("kernel", "user"):
                cfg_names.add(f"{mname}.{kind}")
        cfg_names.add(self.primary)
        cfg_names.update(self.clients.keys())
        cfg_names.update(self._machine_info.keys())
        now = time.time()
        for name in sorted(cfg_names):
            try:
                t = self.cfg.target_for(name)
                cfg_endpoint = f"{t.host}:{t.port}"
            except Exception:
                cfg_endpoint = ""
            client = self.clients.get(name)
            machine_info = self.machine_label(name)
            if client is None:
                rows.append({"name": name, "endpoint": cfg_endpoint,
                             "machine": machine_info["machine"],
                             "computer_name": machine_info["computer_name"],
                             "state": "not_connected", "connected": False})
                continue
            last_op = client.last_op_ts
            state = "connected"
            if last_op and (now - last_op) > 60:
                state = "connected_stale"
            row: dict[str, Any] = {
                "name": name,
                "machine": machine_info["machine"],
                "computer_name": machine_info["computer_name"],
                "endpoint": client.endpoint or cfg_endpoint,
                "configured_endpoint": cfg_endpoint,
                "state": state,
                "connected": True,
                "connected_ts": _dt.datetime.utcfromtimestamp(client.connected_ts).isoformat() + "Z"
                                if client.connected_ts else None,
                "last_seen_ts": _dt.datetime.utcfromtimestamp(client.last_seen_ts).isoformat() + "Z"
                                if client.last_seen_ts else None,
                "last_op_ts": _dt.datetime.utcfromtimestamp(client.last_op_ts).isoformat() + "Z"
                              if client.last_op_ts else None,
                "seconds_since_last_op": round(now - last_op, 1) if last_op else None,
                "primary": (name == self.primary),
            }
            rows.append(row)
        return rows

    def record_tool_call(self, tool: str, action: str, args: dict[str, Any] | None = None,
                         ok: bool = True, error: str = "") -> ToolCall:
        call = ToolCall(
            tool=tool,
            action=action,
            destructive=(tool, action) in DESTRUCTIVE_ACTIONS,
            args=args or {},
            ok=ok,
            error=error,
        )
        self.tool_log.append(call)
        if len(self.tool_log) > 2000:
            del self.tool_log[: len(self.tool_log) - 2000]
        # v0.17 E-2b: mirror to the persistent JSONL sink so the ring's
        # 2000-row cap + orchestrator-restart wipe doesn't lose forensic
        # history. The writer swallows I/O errors internally so a bad
        # disk never masks the tool call itself.
        try:
            self._audit.write({
                "ts": call.ts,
                "tool": tool,
                "action": action,
                "destructive": call.destructive,
                "args": call.args,
                "ok": ok,
                "error": error,
                # `_current_owner` is threaded in by tools that know their
                # client_id (bp_manage / exec_manage / watchdog_manage);
                # absent for older call sites, which show up as
                # `owner: null` on the audit query.
                "owner": (args or {}).get("_current_owner"),
            })
        except Exception:  # noqa: BLE001 — audit must never mask the call
            pass
        return call

    def assert_allowed(self, tool: str, action: str, args: dict[str, Any] | None = None) -> None:
        args = args or {}
        if tool == "target_manage" and action == "driver_load" and not self.cfg.security.allow_driver_load:
            raise PermissionError("driver_load disabled by config")
        if tool == "target_manage" and action == "driver_unload" and not self.cfg.security.allow_driver_unload:
            raise PermissionError("driver_unload disabled by config")
        if tool == "file_manage" and action == "delete":
            if self.cfg.security.allow_delete:
                return
            if not args.get("no_trash"):
                # trash-safe delete stays available with allow_delete=false
                return
            raise PermissionError(
                "allow_delete=false: hard delete (no_trash) refused; trash-safe delete still available"
            )
        # Part 3: evidence_prune is the only destructive knowledge_manage
        # action — gated behind the same allow_delete switch.
        if tool == "knowledge_manage" and action == "evidence_prune" \
                and not self.cfg.security.allow_delete:
            raise PermissionError(
                "allow_delete=false: evidence_prune refused; set "
                "security.allow_delete=true to enable evidence deletion"
            )
