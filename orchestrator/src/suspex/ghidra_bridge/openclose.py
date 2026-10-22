"""Open/close/dispatch mixin: ghidra_open, ghidra_close, ghidra_manage
action routing."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from .errors import GhidraBridgeError
from .helpers import _classify_pdb, _classify_symbols, _safe_int, _valid_session_name

log = logging.getLogger(__name__)

# A pending open sitting in symbols=loading past this many seconds is
# flagged (warning + open_elapsed_s) — Ghidra auto-analysis of a huge
# driver can legitimately run for tens of minutes, so the warn budget
# is generous.
_ANALYSIS_WARN_S = 300.0


class GhidraOpenCloseMixin:
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
        the IDA bridge uses so callers can swap engines verbatim."""
        p = Path(path)
        if p.is_absolute() and p.is_file():
            return p
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
        rooted = self.artifacts_dir.parent / path
        if rooted.is_file():
            return rooted
        raise GhidraBridgeError(
            f"ghidra_manage open: input binary not found: {path!r} "
            f"(tried store-relative {str(alt)!r}, CWD-relative, and "
            f"repo-rooted {str(rooted)!r}); dump it first via "
            f"file_manage(action='dump_module') or pass an absolute path")

    def _validate_open_name(self, requested: str, path: str) -> None:
        """Refuse an open whose name is either outside the accepted
        charset or already reserved for a *different* input path.

        Raises :class:`GhidraBridgeError` with a ``session_exists:``
        prefix so the error envelope maps to the ``session_exists``
        kind.
        """
        if not _valid_session_name(requested):
            raise GhidraBridgeError(
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
                raise GhidraBridgeError(
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
                raise GhidraBridgeError(
                    f"session_exists: name {requested!r} is already "
                    f"open (pending) on {pending[1]!r}; close it first "
                    "or pick a different name"
                )

    def _synthesize_public_name(self, base: str) -> str:
        """Append a short hex suffix until we find an unused public name."""
        for _ in range(16):
            candidate = f"{base}#{uuid.uuid4().hex[:6]}"
            if (candidate not in self._sessions
                    and candidate not in self._pending_opens):
                return candidate
        return f"{base}#{uuid.uuid4().hex}"

    def _resolve_open_public_name(
        self, requested: str, binary_path: Path,
        owner: str | None, share: bool,
    ) -> tuple[str, str | None]:
        """Decide the public name (and any share target) for an open().

        Returns ``(resolved_public_name, shared_session_id_or_None)`` —
        same matrix as the IDA bridge: first claimant wins; same
        (owner|share|adopted, same path) joins; different owner or path
        synthesizes ``<name>#<hex>``.
        """
        path_str = str(binary_path)
        pending = self._pending_opens.get(requested)
        existing_sid = self._sessions.get(requested)
        existing_owner = self._sessions_owner.get(requested)
        existing_path = self._session_paths.get(requested)
        pending_path = pending[1] if pending is not None else None

        if pending is not None and pending_path != path_str:
            return self._synthesize_public_name(requested), None

        if existing_sid is None and pending is None:
            return requested, None

        if existing_path is None or existing_path == path_str:
            if share or existing_owner is None or existing_owner == owner:
                return requested, existing_sid
            return self._synthesize_public_name(requested), None

        return self._synthesize_public_name(requested), None

    async def _open_task_for(
        self, binary_path: Path, requested_name: str,
        run_auto_analysis: bool,
        owner: str | None = None, share: bool = False,
    ) -> tuple[asyncio.Task[str], str]:
        """Return ``(task, resolved_public_name)`` for the requested open."""
        await self.ensure_started()
        self._require_tool("ghidra_open")
        name, shared_sid = self._resolve_open_public_name(
            requested_name, binary_path, owner, share,
        )

        # Fast-path: (name, path) matched an existing session -> record
        # co-ownership and hand back a completed task with the cached sid.
        if shared_sid is not None and name in self._sessions:
            if owner is not None and self._sessions_owner.get(name) != owner:
                self._co_owners.setdefault(name, set()).add(owner)
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
                if prev_path != str(binary_path):
                    raise GhidraBridgeError(
                        f"ghidra_bridge: open_database(name={name!r}, "
                        f"path={binary_path}) conflicts with an in-flight "
                        f"open for the same name but a different path "
                        f"({prev_path}). Wait for it to finish or close "
                        "that session first."
                    )
                if (owner is not None
                        and self._sessions_owner.get(name) != owner):
                    self._co_owners.setdefault(name, set()).add(owner)
                self._touch_mru(name)
                return task, name

        args: dict[str, Any] = {
            "input_path": str(binary_path),
            "mode": "headless",
            "run_auto_analysis": run_auto_analysis,
            "preferred_session_id": name,
        }
        public_name = name

        async def _do_open() -> str:
            text = await self.call_tool("ghidra_open", args)
            if text.startswith("ERROR:"):
                raise GhidraBridgeError(
                    f"ghidra_bridge: ghidra_open failed for {binary_path.name}: {text}\n"
                    "Note: a valid dump loads only after successful import+analysis; check the artifact."
                )
            # the session id is echoed in the tool output; cache it for `database=`
            sid = self._extract_session_id(text) or public_name
            self._sessions[public_name] = sid
            # a live backend now exists — pull the real tool inventory
            # once so the backend tools reach list/schemas output.
            await self._refresh_tools_for_live_backend()
            self._touch_mru(public_name)
            self._manifest_sessions.pop(public_name, None)
            self._save_manifest()
            return sid

        task = asyncio.create_task(_do_open())
        self._pending_opens[name] = (task, str(binary_path))
        self._open_started_at[name] = time.monotonic()
        self._sessions_owner.setdefault(name, owner)
        self._co_owners.setdefault(name, set())
        self._session_paths.setdefault(name, str(binary_path))
        return task, name

    async def open_database_async(
        self, binary_path: Path,
        preferred_name: str | None = None,
        return_after_s: float = 5.0,
        run_auto_analysis: bool = True,
        owner: str | None = None, share: bool = False,
    ) -> dict[str, Any]:
        """Non-blocking open: returns ready|pending within `return_after_s`.

        A 100 MB kernel driver's first Ghidra analysis can outrun any
        reasonable client-side deadline — this is the primary open path.
        Poll ``open_status(name)`` (using the RETURNED ``name``, which
        may be ``<preferred_name>#<hex>`` on a peer collision).
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
            probe = await self._probe_ghidra_status(name)
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
                    "hint": "poll ghidra_manage(action='open_status', name='"
                            + name + "') or ghidra_manage(action='list') "
                            "-- session appears in `sessions` once ready"}

    async def open_status(self, name: str) -> dict[str, Any]:
        """Report state of an open_database_async call by preferred name.

        On the ``ready`` path this runs a cheap live probe
        (:meth:`_probe_ghidra_status`) so callers can distinguish
        "symbols loaded" from "analysis produced nothing". Every
        envelope carries ``open_elapsed_s``; a pending open past
        ``_ANALYSIS_WARN_S`` gains a warning naming the escape hatches.
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
                    "hint": "call ghidra_manage(action='open', path='...', "
                            "preferred_session_id='" + name + "') first"}
        elif not task.done():
            out = {"status": "pending", "name": name,
                   "symbols": "loading", "named_functions": 0,
                   "pdb": "unknown"}
            if elapsed is not None:
                out["open_elapsed_s"] = elapsed
                warn_s = (getattr(self.cfg, "analysis_warn_s", None)
                          or _ANALYSIS_WARN_S)
                if elapsed >= warn_s:
                    out["warnings"] = [
                        f"open has been pending for {elapsed:.0f}s — "
                        "Ghidra analysis of a large driver can be slow, "
                        "but this may also be a wedged import. Options: "
                        "keep polling, close + reopen with "
                        "run_auto_analysis=false, or check "
                        "ghidra_manage(action='ghidra_log')."
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
        # ready path: enrich with a best-effort ghidra_status probe.
        probe = await self._probe_ghidra_status(name)
        base["symbols"] = _classify_symbols(probe)
        base["named_functions"] = _safe_int(probe.get("functions_count"))
        base["pdb"] = _classify_pdb(probe)
        return base

    async def _probe_ghidra_status(self, name: str) -> dict[str, Any]:
        """Run ``ghidra_status`` against a live session; empty dict on
        failure.

        Best-effort: any transport / shim error is swallowed so a
        transient probe hiccup never flips a ``ready`` envelope into an
        ``error``. Skips entirely when ``ghidra_status`` isn't in the
        cached tool inventory (pre-first-backend inventory).
        """
        if "ghidra_status" not in self._tools:
            return {}
        try:
            args = await self.resolve_database(name)
        except GhidraBridgeError:
            return {}
        try:
            text = await self.call_tool("ghidra_status", args)
        except GhidraBridgeError:
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
        """ghidra_open the binary; returns an envelope dict
        ``{status, name, session_id?, owner, shared, requested_name}``.

        ``status`` is ``"ready"`` normally and ``"pending"`` when
        import+analysis blows past ``cfg.open_soft_deadline_s`` — poll
        ``ghidra_manage(action='open_status', name=name)`` from there.
        """
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
            probe = await self._probe_ghidra_status(name)
            return {
                "status": "ready", "session_id": sid, **envelope,
                "symbols": _classify_symbols(probe),
                "named_functions": _safe_int(probe.get("functions_count")),
                "pdb": _classify_pdb(probe),
            }
        except asyncio.TimeoutError:
            return await self.open_database_async(
                binary_path, preferred_name=name, return_after_s=0.0,
                run_auto_analysis=run_auto_analysis,
                owner=owner, share=share,
            )

    @staticmethod
    def _extract_session_id(text: str) -> str | None:
        # shim returns JSON: {"success": true, "session": {"session_id": ...}}
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
        purge: bool = False,
    ) -> str:
        """Close, detach, or hand off a session by public name.

        Ownership rules identical to the IDA bridge: co-owner close ->
        ``detached``; foreign caller -> refused; primary leaving with
        co-owners remaining -> ``handover``; last owner / force / legacy
        -> real ``ghidra_close``.

        ``purge=True`` deletes the program from the shared project
        entirely (the shim's ``delete_project_binary``); the default
        ``save`` release keeps it reopenable.
        """
        self._require_tool("ghidra_close")
        primary = self._sessions_owner.get(name)
        co = self._co_owners.setdefault(name, set())

        if owner is not None and not force and owner in co:
            co.discard(owner)
            return json.dumps({
                "status": "detached", "name": name,
                "remaining_owners": ([primary] if primary is not None else [])
                                    + sorted(co),
            })

        if (owner is not None and not force
                and primary is not None and primary != owner):
            raise GhidraBridgeError(
                f"ghidra_bridge: close_database(name={name!r}) refused: "
                f"session owned by {primary!r}, current caller {owner!r} "
                "is neither the primary owner nor a co-owner. Pass "
                "force=True to override."
            )

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

        args = await self.resolve_database(name, current_owner=owner)
        args["save"] = save
        if purge:
            args["purge"] = True
        out = await self.call_tool("ghidra_close", args)
        self._sessions.pop(name, None)
        self._sessions_owner.pop(name, None)
        self._co_owners.pop(name, None)
        self._session_paths.pop(name, None)
        self._open_started_at.pop(name, None)
        self._rotate_mru_after_close(name)
        self._manifest_sessions.pop(name, None)
        self._save_manifest()
        return out

    # --------------------------------------------------------- action mapping ----

    # Short action verbs in ghidra_manage map to the real MCP tools the
    # backend registers; any unlisted action is treated as a verbatim
    # backend tool name (passthrough).
    ACTION_TOOLS = {
        "open": "ghidra_open",
        "list": "ghidra_list",
        "close": "ghidra_close",
        "decompile": "decompile_function",
        "disasm": "disassemble_function",
        "pcode": "get_pcode",
        "xrefs": "list_xrefs",
        "funcs": "list_functions",
        "types": "list_data_types",
        "strings": "search_strings",
        "imports": "list_imports",
        "exports": "list_exports",
        "segments": "list_segments",
        "analyze": "get_metadata",
        "ctx": "ghidra_query_context",
        "status": "ghidra_status",
        "log": "ghidra_log",
        "job_start": "ghidra_job_start",
        "job_status": "ghidra_job_status",
        "result": "ghidra_result",
        "job_cancel": "ghidra_job_cancel",
        "job_list": "ghidra_job_list",
    }

    # actions that don't map to a shim tool — handled entirely bridge-side
    BRIDGE_ACTIONS = ("open_async", "open_status")

    async def ghidra_manage(self, action: str, name: str | None = None,
                            args: dict[str, Any] | None = None,
                            owner: str | None = None) -> str:
        # open_status doesn't need the shim at all (it queries an
        # orchestrator-side task). Answer before ensure_started so a
        # caller polling during a slow first open doesn't race a spawn.
        call_args_early: dict[str, Any] = dict(args or {})
        if owner is None:
            owner = call_args_early.pop("owner", None)
        else:
            call_args_early.pop("owner", None)
        if action == "open_status":
            if not name:
                raise GhidraBridgeError("ghidra_manage open_status requires 'name'")
            await self.ensure_started()
            return json.dumps(await self.open_status(name))
        await self.ensure_started()
        if action == "open_async":
            path = call_args_early.pop("path", None)
            if not path:
                raise GhidraBridgeError("ghidra_manage open_async requires 'path'")
            binary_path = self._resolve_binary_path(path)
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
        # verbs; any other action is treated as a direct backend tool
        # name (decompile_function, get_pcode, rename_function, ...) so
        # every capability the backend registers is reachable.
        tool = self.ACTION_TOOLS.get(action)
        if tool is None:
            if action in self._tools:
                tool = action
            else:
                offered = ", ".join(sorted(set(self.ACTION_TOOLS)
                                           | set(self._tools)
                                           | set(self.BRIDGE_ACTIONS)))
                raise GhidraBridgeError(
                    f"ghidra_bridge: unknown ghidra_manage action {action!r}. "
                    f"Available: {offered}"
                )
        self._require_tool(tool)
        call_args: dict[str, Any] = dict(args or {})
        if action == "list":
            call_args = {}
        elif action == "open":
            path = call_args.pop("path", None)
            if not path:
                raise GhidraBridgeError("ghidra_manage open requires 'path'")
            binary_path = self._resolve_binary_path(path)
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
                raise GhidraBridgeError("ghidra_manage close requires 'name'")
            return await self.close_database(
                name,
                save=bool(call_args.pop("save", True)),
                owner=call_args.pop("owner", owner),
                force=bool(call_args.pop("force", False)),
                purge=bool(call_args.pop("purge", False)))
        elif name and "database" not in call_args:
            # Name known only from the manifest (post-restart)? Lazy-
            # reopen so the caller doesn't have to know they need to
            # re-open first.
            if (name not in self._sessions
                    and name in self._manifest_sessions):
                await self._maybe_lazy_reopen(name, owner=owner)
            # every non-session tool routes by `database` under the hood;
            # the shim also falls back to the single-session case, but
            # once two programs are open the name is required.
            call_args.update(await self.resolve_database(
                name, current_owner=owner))
        return await self.call_tool(tool, call_args)
