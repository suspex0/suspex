"""Open/close/dispatch mixin: idb_open, idb_close, ida_manage action routing."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from .errors import IdaBridgeError
from .helpers import _classify_pdb, _classify_symbols, _safe_int, _valid_session_name

log = logging.getLogger(__name__)

# v0.24: a pending open sitting in symbols=loading past this many seconds
# is flagged (warning + open_elapsed_s) instead of silently churning —
# the 20-min "is it applying or wedged?" ambiguity from the kernel-PDB
# engagement. Configurable per-bridge via cfg.pdb_apply_warn_s.
_PDB_APPLY_WARN_S = 300.0


class IdaOpenCloseMixin:
    """Session-open / close / action-dispatch surface of the bridge."""

    # ------------------------------------------------------------- database ----

    async def store_binary(self, data: bytes, original_name: str) -> Path:
        digest = hashlib.sha256(data).hexdigest()
        out_dir = self.artifacts_dir / digest
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / Path(original_name).name
        path.write_bytes(data)
        return path

    def _resolve_binary_path(self, path: str) -> Path:
        """open/open_async path= accepts absolute paths, artifacts-
        relative paths (``dumps/ntoskrnl.exe``), store-prefixed paths
        (``artifacts/dumps/x.sys`` — the leading component is stripped,
        not double-rooted), and CWD-relative paths — the same convention
        ``_artifacts.resolve_artifact_path`` gives the tool layer.
        ``self.artifacts_dir`` is the canonical root the orchestrator
        config anchors at the repo root, so resolution is cwd-
        independent."""
        p = Path(path)
        if p.is_absolute() and p.is_file():
            return p
        # Store-relative spellings first: strip a leading component that
        # names the artifacts dir ('artifacts', or the root's own name)
        # and join under the canonical root — this wins over a bare
        # CWD-relative hit so 'artifacts/dumps/x.sys' can never open a
        # stale <cwd>/artifacts shadow.
        parts = [seg for seg in p.parts if seg not in ("", ".")]
        if parts and parts[0].lower() in ("artifacts",
                                         self.artifacts_dir.name.lower()):
            parts = parts[1:]
        alt = self.artifacts_dir.joinpath(*parts) if parts \
            else self.artifacts_dir
        if alt.is_file():
            return alt
        if p.is_file():
            return p
        # abs_path-style inputs already carry the artifacts/ prefix
        # (file_manage ingest returns them); re-root at the parent so
        # they don't double-prefix when the CWD isn't the repo root.
        rooted = self.artifacts_dir.parent / path
        if rooted.is_file():
            return rooted
        raise IdaBridgeError(
            f"ida_manage open: input binary not found: {path!r} "
            f"(tried store-relative {str(alt)!r}, CWD-relative, and "
            f"repo-rooted {str(rooted)!r}); dump it first via "
            f"file_manage(action='dump_module') or pass an absolute path")

    def _validate_open_name(self, requested: str, path: str) -> None:
        """v0.17 C1-1: refuse an ida_manage open whose name is either
        outside the accepted charset (traversal / metachars / too long)
        or already reserved for a *different* input path.

        Raises :class:`IdaBridgeError` with a ``session_exists:`` prefix
        so ``_error_enrich`` maps the failure to the reserved
        ``session_exists`` kind (see ``_shared.md`` §0.4).

        Peer collisions on a live session (different owner, same name,
        different path) still fall through to the existing silent
        ``<name>#<hex>`` synth in :meth:`_resolve_open_public_name`;
        this helper only catches the same-caller-reopens-with-a-
        different-path mistake that was previously silently masked.
        """
        if not _valid_session_name(requested):
            raise IdaBridgeError(
                f"session_exists: invalid session name {requested!r}; "
                f"allowed: 1..64 chars from [A-Za-z0-9_.-]"
            )
        try:
            new_resolved = Path(path).resolve(strict=False)
        except OSError:
            new_resolved = Path(path)
        existing_path = self._session_paths.get(requested)
        if existing_path is not None:
            try:
                existing_resolved = Path(existing_path).resolve(
                    strict=False)
            except OSError:
                existing_resolved = Path(existing_path)
            if existing_resolved != new_resolved:
                raise IdaBridgeError(
                    f"session_exists: name {requested!r} is already "
                    f"open on {existing_path!r}; close it first or "
                    "pick a different name"
                )
        pending = self._pending_opens.get(requested)
        if pending is not None:
            try:
                pending_resolved = Path(pending[1]).resolve(strict=False)
            except OSError:
                pending_resolved = Path(pending[1])
            if pending_resolved != new_resolved:
                raise IdaBridgeError(
                    f"session_exists: name {requested!r} is already "
                    f"open (pending) on {pending[1]!r}; close it first "
                    "or pick a different name"
                )

    def _synthesize_public_name(self, base: str) -> str:
        """Append a short hex suffix until we find an unused public name.

        Used when caller-B's `preferred_session_id` collides with caller-A's
        for a *different* binary: caller-B is silently promoted to
        ``<base>#<hex>`` rather than raising, so both sessions coexist.
        """
        for _ in range(16):
            candidate = f"{base}#{uuid.uuid4().hex[:6]}"
            if (candidate not in self._sessions
                    and candidate not in self._pending_opens):
                return candidate
        # extremely unlikely at 24 bits; widen and give up on retry loop.
        return f"{base}#{uuid.uuid4().hex}"

    def _resolve_open_public_name(
        self, requested: str, binary_path: Path,
        owner: str | None, share: bool,
    ) -> tuple[str, str | None]:
        """Decide the public name (and any share target) for an open().

        Returns ``(resolved_public_name, shared_session_id_or_None)``:

        - name unused             -> (requested, None)   # first claimant wins
        - same owner, same path   -> (requested, existing_sid)
        - share=True, same path   -> (requested, existing_sid)   # co-own
        - adopted (owner=None)    -> (requested, existing_sid)   # claim it
        - different owner or path -> (synthesized, None)         # peer dbs

        In-flight pending opens follow the same rule via the recorded
        pending path, so a peer collision spawns a fresh open under a
        synthesized name rather than joining someone else's open.
        """
        path_str = str(binary_path)
        pending = self._pending_opens.get(requested)
        existing_sid = self._sessions.get(requested)
        existing_owner = self._sessions_owner.get(requested)
        existing_path = self._session_paths.get(requested)
        pending_path = pending[1] if pending is not None else None

        # Path mismatch against an in-flight open -> always synthesize
        # (never redirect a running idb_open onto a different binary).
        if pending is not None and pending_path != path_str:
            return self._synthesize_public_name(requested), None

        # Name entirely unused: take it.
        if existing_sid is None and pending is None:
            return requested, None

        # Path matches (or is unrecorded on an adopted session): allow
        # same-owner reuse, share=True, or claim of an adopted session.
        if existing_path is None or existing_path == path_str:
            if share or existing_owner is None or existing_owner == owner:
                return requested, existing_sid
            return self._synthesize_public_name(requested), None

        # Path mismatch against a completed session -> synthesize.
        return self._synthesize_public_name(requested), None

    async def _open_task_for(
        self, binary_path: Path, requested_name: str,
        run_auto_analysis: bool,
        owner: str | None = None, share: bool = False,
    ) -> tuple[asyncio.Task[str], str]:
        """Return ``(task, resolved_public_name)`` for the requested open.

        Shared by open_database and open_database_async so a caller that
        upgrades from sync to async — or a sync caller whose soft deadline
        elapsed and re-polled via open_status — always joins the same
        shielded task instead of firing a second idb_open at the shim.

        The resolved public name may differ from ``requested_name`` when
        another owner already holds that name for a different path:
        rather than raising, the peer is silently assigned
        ``<requested_name>#<hex>``. When ``share=True`` and the (name,
        path) pair matches an existing session, ``owner`` is added to the
        co-owner set and a trivially-done task holding the existing
        session id is returned so the caller's sync/async return shape is
        preserved.
        """
        await self.ensure_started()
        self._require_tool("idb_open")
        name, shared_sid = self._resolve_open_public_name(
            requested_name, binary_path, owner, share,
        )

        # Fast-path: (name, path) matched an existing session -> record
        # co-ownership and hand back a completed task with the cached sid.
        if shared_sid is not None and name in self._sessions:
            if owner is not None and self._sessions_owner.get(name) != owner:
                self._co_owners.setdefault(name, set()).add(owner)
            # v0.17 C1-3: an open that resolves to an existing session
            # still counts as a touch (the caller now has this session
            # in hand and any follow-up call should default to it).
            self._touch_mru(name)

            async def _instant(sid: str = shared_sid) -> str:
                return sid
            return asyncio.create_task(_instant()), name

        # Same-owner (or share) joining an in-flight open under the same
        # path -> return the running task.
        pending = self._pending_opens.get(name)
        if pending is not None:
            task, prev_path = pending
            if not task.done():
                # _resolve_open_public_name only steers here when paths
                # match; the guard stays as belt-and-suspenders.
                if prev_path != str(binary_path):
                    raise IdaBridgeError(
                        f"ida_bridge: open_database(name={name!r}, "
                        f"path={binary_path}) conflicts with an in-flight "
                        f"open for the same name but a different path "
                        f"({prev_path}). Wait for it to finish or close "
                        "that session first."
                    )
                if (owner is not None
                        and self._sessions_owner.get(name) != owner):
                    self._co_owners.setdefault(name, set()).add(owner)
                # v0.17 C1-3: also touch when we join a pending open.
                self._touch_mru(name)
                return task, name

        args: dict[str, Any] = {
            "input_path": str(binary_path),
            "mode": "prefer_gui" if self.cfg.prefer_gui else "prefer_headless",
            "run_auto_analysis": run_auto_analysis,
            "preferred_session_id": name,
        }
        public_name = name

        async def _do_open() -> str:
            text = await self.call_tool("idb_open", args)
            if text.startswith("ERROR:"):
                raise IdaBridgeError(
                    f"ida_bridge: idb_open failed for {binary_path.name}: {text}\n"
                    "Note: a valid dump loads only after successful analysis; check the artifact."
                )
            # the session id is echoed in the tool output; cache it for `database=`
            sid = self._extract_session_id(text) or public_name
            self._sessions[public_name] = sid
            # v0.24: a live backend now exists — pull the real tool
            # inventory once so extension tools (exec_idapython,
            # pattern_scan, ...) reach list/schemas output without a
            # manual refresh.
            await self._refresh_tools_for_live_backend()
            # v0.17 C1-3: mark this as the MRU once idb_open actually
            # succeeds — a failed open must NOT rotate MRU (would send
            # every subsequent auto-fill onto a stale name).
            self._touch_mru(public_name)
            # v0.17 C1-4: the live session now supersedes any manifest
            # entry (which held only the pre-restart hint); persist so
            # a same-name crash-and-reopen path reads back this open.
            self._manifest_sessions.pop(public_name, None)
            self._save_manifest()
            return sid

        task = asyncio.create_task(_do_open())
        self._pending_opens[name] = (task, str(binary_path))
        self._open_started_at[name] = time.monotonic()
        # Record ownership / path as soon as the open is dispatched, so a
        # concurrent peer's _resolve_open_public_name sees the claim and
        # synthesizes rather than racing us onto the same public name.
        self._sessions_owner.setdefault(name, owner)
        self._co_owners.setdefault(name, set())
        self._session_paths.setdefault(name, str(binary_path))
        return task, name

    async def open_database_async(
        self, binary_path: Path,
        preferred_name: str | None = None,
        return_after_s: float = 5.0,
        run_auto_analysis: bool = True,
        owner: str | None = None,
        share: bool = False,
    ) -> dict[str, Any]:
        """Non-blocking open: returns ready|pending within `return_after_s`.

        A 100 MB kernel driver's first idalib analysis can outrun any
        reasonable client-side gRPC deadline. This wraps the blocking
        open_database in an asyncio Task so the caller doesn't have to
        stay on the wire. Poll ``open_status(name)`` (using the RETURNED
        ``name``, which may be ``<preferred_name>#<hex>`` if another
        owner already held that friendly name for a different path).

        ``owner`` tags the primary owner (typically a client_id). When
        ``share=True`` and (name, path) matches a live session, the
        caller is added as a co-owner and the existing session id is
        returned; close_database with the same ``owner`` will only
        detach, not tear down, until the last owner leaves.
        """
        requested = preferred_name or f"db_{uuid.uuid4().hex[:8]}"
        task, name = await self._open_task_for(
            binary_path, requested, run_auto_analysis,
            owner=owner, share=share,
        )
        envelope = {
            "requested_name": requested,
            "name": name,
            "owner": self._sessions_owner.get(name),
            "shared": bool(
                owner is not None
                and owner in self._co_owners.get(name, set())
            ),
        }
        try:
            sid = await asyncio.wait_for(asyncio.shield(task), timeout=return_after_s)
            # v0.17 C1-2: enrich the ready envelope with the same
            # symbols/named_functions/pdb triple open_status emits, so
            # a caller who blocks through the open doesn't need a
            # follow-up poll to learn whether PDB actually matched.
            probe = await self._probe_ida_status(name)
            return {
                "status": "ready", "session_id": sid, **envelope,
                "symbols": _classify_symbols(probe),
                "named_functions": _safe_int(probe.get("functions_count")),
                "pdb": _classify_pdb(probe),
            }
        except asyncio.TimeoutError:
            return {"status": "pending", **envelope,
                    "symbols": "loading", "named_functions": 0,
                    "pdb": "unknown",
                    "hint": "poll ida_manage(action='open_status', name='"
                            + name + "') or ida_manage(action='list') "
                            "-- session appears in `sessions` once ready"}

    async def open_status(self, name: str) -> dict[str, Any]:
        """Report state of an open_database_async call by preferred name.

        v0.17 C1-2: on the ``ready`` path this runs a cheap live
        probe (:meth:`_probe_ida_status`) so callers can distinguish
        "symbols loaded" from "PDB fetch silently failed" without
        first hitting a name search that returns zero rows. Three
        fields land in every response:

          ``symbols``          loading | loaded | failed | none
          ``named_functions``  int (may be 0 during early load)
          ``pdb``              matched | missing | failed | unknown

        v0.24: every envelope also carries ``open_elapsed_s`` so
        "symbols: loading for 20+ min" is visible without a stopwatch,
        and a pending open past ``pdb_apply_warn_s`` gains a warning
        naming the escape hatches.

        The probe is best-effort: any transport / shim error leaves
        the fields at ``unknown`` so a live-probe hiccup never
        downgrades a ``ready`` reply to ``error``. Terminal states
        (``cancelled``/``error``/``unknown``) skip the probe.
        """
        entry = self._pending_opens.get(name)
        task = entry[0] if entry is not None else None
        cached = self._sessions.get(name)
        started = self._open_started_at.get(name)
        elapsed = (round(time.monotonic() - started, 1)
                   if started is not None else None)
        if task is None and cached:
            base = {"status": "ready", "name": name, "session_id": cached}
        elif task is None:
            return {"status": "unknown", "name": name,
                    "hint": "call ida_manage(action='open', path='...', "
                            "preferred_session_id='" + name + "') first"}
        elif not task.done():
            # Analysis still churning: mark symbols=loading so the
            # poller doesn't confuse it with "auto-analysis idled with
            # zero functions" (the `failed` bucket below).
            out = {"status": "pending", "name": name,
                   "symbols": "loading", "named_functions": 0,
                   "pdb": "unknown"}
            if elapsed is not None:
                out["open_elapsed_s"] = elapsed
                warn_s = (getattr(self.cfg, "pdb_apply_warn_s", None)
                          or _PDB_APPLY_WARN_S)
                if elapsed >= warn_s:
                    out["warnings"] = [
                        f"open has been pending for {elapsed:.0f}s — "
                        "likely a slow or wedged PDB apply. Options: keep "
                        "polling, close + reopen with run_auto_analysis="
                        "false, or use bin_manage for pure-parse questions."
                    ]
            return out
        elif task.cancelled():
            return {"status": "cancelled", "name": name}
        else:
            exc = task.exception()
            if exc is not None:
                return {"status": "error", "name": name,
                        "error": f"{type(exc).__name__}: {exc}"}
            base = {"status": "ready", "name": name,
                    "session_id": task.result()}
        if elapsed is not None:
            base["open_elapsed_s"] = elapsed
        # ready path: enrich with a best-effort ida_status probe.
        probe = await self._probe_ida_status(name)
        base["symbols"] = _classify_symbols(probe)
        base["named_functions"] = _safe_int(probe.get("functions_count"))
        base["pdb"] = _classify_pdb(probe)
        return base

    async def _probe_ida_status(self, name: str) -> dict[str, Any]:
        """Run ``ida_status`` against a live session; empty dict on failure.

        Best-effort: any wire / shim error is swallowed here so a
        transient probe hiccup can never flip a ``ready`` envelope
        into an ``error`` response. The empty return makes every
        classifier fall through to ``unknown``.

        Skips the probe entirely when ``ida_status`` isn't registered
        by the current shim (vanilla ida-pro-mcp without our
        ``suspex_idalib_ext`` — a valid config for callers who only
        care about the vendor tools).
        """
        if "ida_status" not in self._tools:
            return {}
        try:
            args = await self.resolve_database(name)
        except IdaBridgeError:
            return {}
        try:
            text = await self.call_tool("ida_status", args)
        except IdaBridgeError:
            return {}
        if text.startswith("ERROR:"):
            return {}
        try:
            data = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    async def open_database(
        self, binary_path: Path, preferred_name: str | None = None,
        run_auto_analysis: bool = True,
        owner: str | None = None, share: bool = False,
    ) -> dict[str, Any]:
        """idb_open the binary; returns an envelope dict
        ``{status, name, session_id?, owner, shared, requested_name}``.

        ``status`` is ``"ready"`` normally and ``"pending"`` when analysis
        blows past ``cfg.open_soft_deadline_s`` — in the pending case the
        in-flight ``tools/call`` keeps running (cancelling would tear the
        shim's SSE stream) and the caller polls
        ``ida_manage(action='open_status', name=name)`` from there.

        The returned ``name`` may differ from ``preferred_name`` when
        another owner already held that friendly name for a different
        path (peer collision -> ``<preferred_name>#<hex>``). Downstream
        ``ida_manage`` calls MUST route by the returned ``name``.

        ``owner`` / ``share`` semantics are identical to
        ``open_database_async``.

        ``run_auto_analysis=False`` skips auto-analysis (via the shim's
        SUSPX_IDA_NO_AUTO env gate on our extension entry) — use for
        huge drivers where you want to control which functions are
        carved (create_function on specific eas, then auto_wait)."""
        # Start the wall-clock at function entry so a cold ensure_started
        # (uv+Python+idalib import, MCP handshake, tools/list refresh --
        # easily 3-6s on Windows) doesn't rob the caller's whole soft
        # budget before we ever hit wait_for.
        loop = asyncio.get_event_loop()
        t0 = loop.time()
        requested = preferred_name or f"db_{uuid.uuid4().hex[:8]}"
        task, name = await self._open_task_for(
            binary_path, requested, run_auto_analysis,
            owner=owner, share=share,
        )
        elapsed = loop.time() - t0
        remaining = max(0.1, self.cfg.open_soft_deadline_s - elapsed)
        envelope = {
            "requested_name": requested,
            "name": name,
            "owner": self._sessions_owner.get(name),
            "shared": bool(
                owner is not None
                and owner in self._co_owners.get(name, set())
            ),
        }
        try:
            sid = await asyncio.wait_for(
                asyncio.shield(task), timeout=remaining
            )
            # v0.17 C1-2: match open_database_async's ready envelope so
            # sync and async open() paths hand the caller the same
            # symbols/named_functions/pdb triple.
            probe = await self._probe_ida_status(name)
            return {
                "status": "ready", "session_id": sid, **envelope,
                "symbols": _classify_symbols(probe),
                "named_functions": _safe_int(probe.get("functions_count")),
                "pdb": _classify_pdb(probe),
            }
        except asyncio.TimeoutError:
            # Re-enter async path with the already-resolved public name so
            # the peer joins the same in-flight task rather than creating a
            # second entry under `requested`.
            return await self.open_database_async(
                binary_path, preferred_name=name, return_after_s=0.0,
                run_auto_analysis=run_auto_analysis,
                owner=owner, share=share,
            )

    @staticmethod
    def _extract_session_id(text: str) -> str | None:
        # shim returns JSON: {"success": true, "session": {"session_id": "...",
        # ...}, ...}. Prefer parsing that; only fall back to token scanning
        # (which historically grabbed the key "session_id" as if it were the
        # value) if the JSON shape is unexpected.
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, dict):
            sess = data.get("session")
            if isinstance(sess, dict) and isinstance(sess.get("session_id"), str):
                return sess["session_id"]
            if isinstance(data.get("session_id"), str):
                return data["session_id"]
        for token in text.split():
            token = token.strip(".,;:()[]\"'")
            if token in ("session_id", "sid"):
                continue
            if token.startswith("sid_") or token.startswith("session_"):
                return token
        return None

    async def close_database(
        self, name: str, save: bool = True,
        owner: str | None = None, force: bool = False,
    ) -> str:
        """Close, detach, or hand off a session by public name.

        Ownership rules (only enforced when ``owner`` is supplied and
        ``force`` is False):

        - ``owner`` is a co-owner: drop from ``co_owners`` and return a
          ``detached`` envelope; the session stays open for the primary
          owner.
        - ``owner`` is not the primary owner and not a co-owner: refuse
          with :class:`IdaBridgeError`.
        - ``owner`` is the primary owner and co-owners remain: promote
          the next co-owner to primary and return a ``handover``
          envelope; the session stays open for them.
        - Otherwise (last owner leaving, or ``force=True``, or
          ``owner=None`` legacy caller): call ``idb_close`` on the shim
          and drop all bookkeeping.

        The plain-text ``idb_close`` result is returned as-is in the
        actual-close case; detach/handover encode the envelope as JSON
        so tools.py can surface the state change to the LLM.
        """
        self._require_tool("idb_close")
        primary = self._sessions_owner.get(name)
        co = self._co_owners.setdefault(name, set())

        # Co-owner detach: no shim call, session stays up.
        if owner is not None and not force and owner in co:
            co.discard(owner)
            return json.dumps({
                "status": "detached", "name": name,
                "remaining_owners": ([primary] if primary is not None else [])
                                    + sorted(co),
            })

        # Foreign caller (not primary, not co-owner) trying a hard close.
        if (owner is not None and not force
                and primary is not None and primary != owner):
            raise IdaBridgeError(
                f"ida_bridge: close_database(name={name!r}) refused: "
                f"session owned by {primary!r}, current caller {owner!r} "
                "is neither the primary owner nor a co-owner. Pass "
                "force=True to override."
            )

        # Primary leaving while co-owners remain -> hand off, keep open.
        if (owner is not None and not force
                and owner == primary and co):
            new_primary = sorted(co)[0]
            co.discard(new_primary)
            self._sessions_owner[name] = new_primary
            return json.dumps({
                "status": "handover", "name": name,
                "new_owner": new_primary,
                "remaining_co_owners": sorted(co),
            })

        # Last owner (or force=True, or legacy owner=None) -> real close.
        args = await self.resolve_database(name, current_owner=owner)
        args["save"] = save
        out = await self.call_tool("idb_close", args)
        self._sessions.pop(name, None)
        self._sessions_owner.pop(name, None)
        self._co_owners.pop(name, None)
        self._session_paths.pop(name, None)
        self._open_started_at.pop(name, None)
        # v0.17 C1-3: rotate MRU after the session is really gone —
        # detach/handover paths already returned above (session stays
        # live, MRU stays the same).
        self._rotate_mru_after_close(name)
        # v0.17 C1-4: close is authoritative — drop the manifest entry
        # so a later restart doesn't offer to re-open a session the
        # user closed intentionally.
        self._manifest_sessions.pop(name, None)
        self._save_manifest()
        return out

    # --------------------------------------------------------- action mapping ----

    # tool names match ida-pro-mcp 1.4.0 / idalib-mcp; short action verbs
    # in ida_manage map to the real MCP tools the backend registers.
    ACTION_TOOLS = {
        "open": "idb_open",
        "list": "idb_list",
        "close": "idb_close",
        "decompile": "decompile_function",
        "disasm": "disassemble_function",
        "xrefs": "get_xrefs_to",
        "funcs": "list_functions",
        "globals": "list_globals",
        "types": "list_local_types",
        "patch": "patch_address_assembles",
        "analyze": "get_metadata",
        "ctx": "ida_query_context",
        # v0.8: job model — short verbs mirror the shim tools.
        "log": "ida_log",
        "job_start": "ida_job_start",
        "job_status": "ida_job_status",
        "result": "ida_result",
        "job_cancel": "ida_job_cancel",
        "job_list": "ida_job_list",
    }

    # actions that don't map to a shim tool — handled entirely bridge-side
    BRIDGE_ACTIONS = ("open_async", "open_status")

    async def ida_manage(self, action: str, name: str | None = None,
                         args: dict[str, Any] | None = None,
                         owner: str | None = None) -> str:
        # open_status doesn't need the shim at all (it queries an
        # orchestrator-side task). Answer before ensure_started so a
        # caller polling during a slow first open doesn't race a spawn.
        call_args_early: dict[str, Any] = dict(args or {})
        # Callers may pass owner either as an explicit kwarg (the new
        # tools.py path) or embedded in args (legacy / passthrough).
        if owner is None:
            owner = call_args_early.pop("owner", None)
        else:
            call_args_early.pop("owner", None)
        if action == "open_status":
            if not name:
                raise IdaBridgeError("ida_manage open_status requires 'name'")
            # v0.17 C1-2: open_status is async now (it runs a live
            # ida_status probe on the ready path). ensure_started is
            # cheap when the shim's already up; on the cold path the
            # probe short-circuits via `ida_status not in _tools`.
            await self.ensure_started()
            return json.dumps(await self.open_status(name))
        await self.ensure_started()
        if action == "open_async":
            path = call_args_early.pop("path", None)
            if not path:
                raise IdaBridgeError("ida_manage open_async requires 'path'")
            binary_path = self._resolve_binary_path(path)
            # v0.17 C1-1: top-level `name` kwarg wins over an
            # args-embedded `preferred_session_id`, and both win over
            # Path(path).stem. Charset + collision validation match the
            # `open` branch below.
            pref = (
                name
                or call_args_early.pop("preferred_session_id", None)
                or Path(path).stem
            )
            self._validate_open_name(pref, path)
            out_dir = self.artifacts_dir / pref
            out_dir.mkdir(parents=True, exist_ok=True)
            wait = float(call_args_early.pop("return_after_s", 5.0) or 5.0)
            raa = bool(call_args_early.pop("run_auto_analysis", True))
            share = bool(call_args_early.pop("share", False))
            return json.dumps(await self.open_database_async(
                binary_path, pref, wait, run_auto_analysis=raa,
                owner=owner, share=share))
        # Resolve the tool name: ACTION_TOOLS is a small set of ergonomic
        # verbs; any other action is treated as a direct idalib-mcp tool
        # name (get_entry_points, list_imports, rename_function, ...) so
        # every static-analysis capability the backend registers is
        # reachable without extending the map.
        tool = self.ACTION_TOOLS.get(action)
        if tool is None:
            if action in self._tools:
                tool = action
            else:
                offered = ", ".join(sorted(set(self.ACTION_TOOLS)
                                           | set(self._tools)
                                           | set(self.BRIDGE_ACTIONS)))
                raise IdaBridgeError(
                    f"ida_bridge: unknown ida_manage action {action!r}. "
                    f"Available: {offered}"
                )
        self._require_tool(tool)
        call_args: dict[str, Any] = dict(args or {})
        if action == "list":
            call_args = {}
        elif action == "open":
            path = call_args.pop("path", None)
            if not path:
                raise IdaBridgeError("ida_manage open requires 'path'")
            binary_path = self._resolve_binary_path(path)
            # v0.17 C1-1: honor caller-supplied `name` verbatim.
            # Precedence: top-level name kwarg > preferred_session_id
            # (legacy args-embedded form) > Path(path).stem. A
            # tcpip.sys opened as `tcpip26200` used to silently
            # collapse to `tcpip` because the top-level kwarg was
            # popped in tools.py but dropped here.
            requested = (
                name
                or call_args.pop("preferred_session_id", None)
                or Path(path).stem
            )
            self._validate_open_name(requested, path)
            out_dir = self.artifacts_dir / requested
            out_dir.mkdir(parents=True, exist_ok=True)
            raa = bool(call_args.pop("run_auto_analysis", True))
            share = bool(call_args.pop("share", False))
            envelope = await self.open_database(
                binary_path,
                requested,
                run_auto_analysis=raa,
                owner=call_args.pop("owner", owner),
                share=share)
            return json.dumps(envelope)
        elif action == "close":
            if not name:
                raise IdaBridgeError("ida_manage close requires 'name'")
            return await self.close_database(
                name,
                save=bool(call_args.pop("save", True)),
                owner=call_args.pop("owner", owner),
                force=bool(call_args.pop("force", False)))
        elif name and "database" not in call_args:
            # v0.17 C1-4: name known only from the manifest (e.g. after
            # an orchestrator restart, or a persistent-worker crash)?
            # Lazy-reopen so the caller doesn't have to know they need
            # to re-open first. Silent unless the .sys is now gone.
            if (name not in self._sessions
                    and name in self._manifest_sessions):
                await self._maybe_lazy_reopen(name, owner=owner)
            # every non-session tool routes by `database` under the hood;
            # the shim also falls back to the single-session case, but
            # once two DBs are open the name is required.
            call_args.update(await self.resolve_database(
                name, current_owner=owner))
        return await self.call_tool(tool, call_args)
