"""Files tool registration for the suspex0 MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)


# v0.24: sha256 cache for list_artifacts' dumps/ingested rows — keyed on
# (path, mtime, size) so an unchanged file hashes exactly once per session.
_ART_HASH_CACHE: dict[tuple[str, float, int], str] = {}


def _artifact_sha256(p, chunk: int = 1 << 20) -> str:
    """sha256 for a local artifacts file, cached on (path, mtime, size).
    Returns "" when the file vanishes mid-walk or hashing fails — a
    listing must never fail because a file was deleted concurrently."""
    try:
        st = p.stat()
        key = (str(p), st.st_mtime, st.st_size)
        hit = _ART_HASH_CACHE.get(key)
        if hit is not None:
            return hit
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    break
                h.update(buf)
        digest = h.hexdigest()
        _ART_HASH_CACHE[key] = digest
        return digest
    except OSError:
        return ""


FILE_ACTIONS = ["upload", "download", "read", "dump_module", "hash",
                "list_dir", "delete", "yara", "tail",
                "follow_start", "follow_poll", "follow_stop",
                "follow_list",
                # v0.13 dev-feedback:
                "grep_artifact",
                # v0.14 auto-spill:
                "read_artifact",
                # v0.16 operational polish:
                "list_artifacts",
                # v0.21 dev-feedback:
                "ingest",
                # v0.22 discoverability:
                "actions"]

_FILE_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "file_manage(action='actions')"},
    "upload": {"one_liner": "local file -> remote path on the target",
               "key_args": "local_path, remote_path",
               "example": "file_manage(action='upload', "
                          "local_path='x.exe', "
                          "remote_path='C:\\\\Temp\\\\x.exe')"},
    "download": {"one_liner": "remote file -> local artifacts dir "
                              "(recursive=true mirrors a remote directory "
                              "tree into artifacts/downloads/)",
                 "key_args": "remote_path, local_path, recursive",
                 "example": "file_manage(action='download', "
                            "remote_path='C:\\\\Temp\\\\out.bin')"},
    "read": {"one_liner": "read remote file bytes inline — ranged "
                          "(offset/length, 4 MiB cap); text-shaped files "
                          "(.txt/.log/.ps1/…) return a `text` field "
                          "automatically, decode= for typed values; "
                          "side='orchestrator' reads an artifacts/spill "
                          "file instead of the target",
             "key_args": "remote_path, offset, length, decode, side",
             "example": "file_manage(action='read', "
                        "remote_path='C:\\\\Temp\\\\out.bin', offset=0, "
                        "length=4096)"},
    "dump_module": {"one_liner": "dump a loaded module as a VA-layout PE "
                                 "(quiesce/unrelocated options; kernel=true "
                                 "for .sys)",
                    "key_args": "pid, module, dump_type, quiesce, kernel",
                    "example": "file_manage(action='dump_module', "
                               "module='x.sys', kernel=true)"},
    "hash": {"one_liner": "sha256 of a remote file",
             "key_args": "remote_path",
             "example": "file_manage(action='hash', "
                        "remote_path='C:\\\\Windows\\\\x.dll')"},
    "list_dir": {"one_liner": "list a remote directory",
                 "key_args": "remote_path, recursive",
                 "example": "file_manage(action='list_dir', "
                            "remote_path='C:\\\\Windows\\\\System32\\\\drivers')"},
    "delete": {"one_liner": "guarded remote delete (recycle-bin unless "
                            "no_trash)",
               "key_args": "remote_path, no_trash",
               "example": "file_manage(action='delete', "
                          "remote_path='C:\\\\Temp\\\\x.exe')"},
    "yara": {"one_liner": "scan a remote file with a YARA rule",
             "key_args": "remote_path, rule | rule_path",
             "example": "file_manage(action='yara', "
                        "remote_path='C:\\\\x.sys', rule='rule r { ... }')"},
    "tail": {"one_liner": "last N bytes of a remote file (no full pull)",
             "key_args": "remote_path, bytes, line_align",
             "example": "file_manage(action='tail', "
                        "remote_path='C:\\\\log.txt', bytes=65536)"},
    "follow_start": {"one_liner": "tail -f — start streaming new file "
                                  "chunks into a ring buffer",
                     "key_args": "remote_path, from_offset, duration_s",
                     "example": "file_manage(action='follow_start', "
                                "remote_path='C:\\\\out.log')"},
    "follow_poll": {"one_liner": "drain buffered follow chunks",
                    "key_args": "follow_id, from_seq",
                    "example": "file_manage(action='follow_poll', "
                               "follow_id='f-1')"},
    "follow_stop": {"one_liner": "stop a follow session",
                    "key_args": "follow_id",
                    "example": "file_manage(action='follow_stop', "
                               "follow_id='f-1')"},
    "follow_list": {"one_liner": "list active follow sessions",
                    "key_args": "none",
                    "example": "file_manage(action='follow_list')"},
    "grep_artifact": {"one_liner": "regex over a spilled artifact (local, "
                                   "no target contact)",
                      "key_args": "sha256, pattern, context, max_matches",
                      "example": "file_manage(action='grep_artifact', "
                                 "sha256='...', pattern='CRITICAL')"},
    "read_artifact": {"one_liner": "read back a spilled response payload "
                                   "from artifacts/spill/",
                      "key_args": "sha256, offset, length, page, page_size",
                      "example": "file_manage(action='read_artifact', "
                                 "sha256='...', page=0)"},
    "list_artifacts": {"one_liner": "list everything under the local "
                                    "artifacts dir",
                       "key_args": "path, recursive",
                       "example": "file_manage(action='list_artifacts')"},
    "ingest": {"one_liner": "copy a local file into artifacts/ so "
                            "bin_manage/ida_manage can work on it",
               "key_args": "local_path, module",
               "example": "file_manage(action='ingest', "
                          "local_path='sample.sys')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``file_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------- file_manage --

    class FileArgs(BaseModel):
        action: str = Field(description=(
            "upload|download|read|dump_module|hash|list_dir|delete|yara|tail|"
            "follow_start|follow_poll|follow_stop|follow_list|grep_artifact|"
            "read_artifact|list_artifacts|ingest"))
        local_path: str = ""
        remote_path: str = ""
        module: str = ""
        pid: int = 0
        path: str = ""
        recursive: bool = False
        no_trash: bool = False
        # v0.25: read verb — which filesystem `remote_path` points at.
        # "target" (default) reads via the agent Download stream;
        # "orchestrator" reads a local artifact path / sha256 (no target
        # contact needed).
        side: str = Field(default="",
                          description="read: 'target'|'orchestrator'")
        decode: Any = Field(default="",
                            description="read: typed decode spec (same as "
                                        "mem_rw read)")
        quiesce: bool = Field(default=False,
                              description="dump_module: suspend target for a consistent image")
        dump_type: str = Field(default="as_loaded",
                               description="dump_module: as_loaded | unrelocated")
        kernel: bool = Field(default=False,
                             description="dump_module: kernel module via "
                                         "PsLoadedModuleList (driver "
                                         "required)")
        rule: str = Field(default="", description="yara: inline rule source")
        rule_path: str = Field(default="", description="yara: local rule file path")
        bytes: int = Field(default=65536,
                           description="tail: bytes from the file end")
        line_align: bool = Field(default=True,
                                 description="tail/follow_*: skip partial "
                                             "first line")
        # follow_* fields
        follow_id: str = Field(default="",
                               description="follow_poll/stop: the id from follow_start")
        from_seq: int = Field(default=0,
                              description="follow_poll: drain chunks since this seq")
        from_offset: int = Field(default=0,
                                 description="follow_start: 0 = backfill "
                                             "tail, -1 = start at EOF")
        pattern: str = Field(default="", description="grep_artifact: Python "
                                                     "regex")
        context: int = Field(default=3, description="grep_artifact: context "
                                                    "lines per match")
        max_matches: int = Field(default=100, description="grep_artifact: "
                                                          "match cap")
        # v0.14 auto-spill: read_artifact fetches a spilled response payload
        # back out of artifacts/spill/. sha256 identifies the artifact; every
        # oversize envelope carries the id in `env.artifact.sha256`.
        sha256: str = Field(default="",
                            description="read_artifact: sha256 of the spilled artifact")
        offset: int = Field(default=0,
                            description="read/read_artifact: byte offset")
        length: int = Field(default=0,
                            description="read/read_artifact: bytes to read "
                                        "(0=to EOF, cap 4 MiB)")
        page: int = Field(default=0,
                          description="read_artifact: page index for .jsonl artifacts")
        page_size: int = Field(default=64,
                               description="read_artifact: rows per page for .jsonl (max 1000)")
        initial_tail_bytes: int = Field(default=65536,
                                        description="follow_start: EOF "
                                                    "backfill bytes")
        poll_interval_ms: int = Field(default=200,
                                      description="follow_start: agent poll "
                                                  "interval (floor 10 ms)")
        max_chunk_bytes: int = Field(default=65536,
                                     description="follow_start: max bytes per chunk")
        follow_rotation: bool = Field(default=True,
                                      description="follow_start: reopen on "
                                                  "size shrink")
        duration_s: int = Field(default=600,
                                description="follow_start: stream lifetime "
                                            "(cap 3600)")
        max_bytes: int = Field(default=0,
                               description="follow_start: 0 = unlimited "
                                           "within duration_s")
        ring_cap: int = Field(default=8192,
                              description="follow_start: chunks buffered "
                                          "per follow_id")
        name: str = Field(default="",
                          description="target view: '' = focused/default "
                                      "machine's kernel view; "
                                      "'<machine>.<kind>' or '<machine>' "
                                      "to pick")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def file_manage(action: Annotated[str, Field(json_schema_extra={"enum": FILE_ACTIONS})],
                          local_path: str = "", remote_path: str = "",
                          module: str = "", pid: int = 0, path: str = "",
                          recursive: bool = False, no_trash: bool = False,
                          side: str = "", decode: Any = "",
                          quiesce: bool = False, dump_type: str = "as_loaded",
                          kernel: bool = False,
                          rule: str = "", rule_path: str = "",
                          bytes: int = 65536, line_align: bool = True,
                          follow_id: str = "", from_seq: int = 0,
                          from_offset: int = 0, initial_tail_bytes: int = 65536,
                          poll_interval_ms: int = 200, max_chunk_bytes: int = 65536,
                          follow_rotation: bool = True, duration_s: int = 600,
                          max_bytes: int = 0, ring_cap: int = 8192,
                          pattern: str = "", context: int = 3,
                          max_matches: int = 100,
                          sha256: str = "", offset: int = 0, length: int = 0,
                          page: int = 0, page_size: int = 64,
                          # v0.14 unified paging (Layer 3)
                          limit: int = 0,
                          cursor: str = "",
                          verbosity: str = "normal",
                          filter: Any = "",
                          summary: bool = False,
                          fields: list[str] | None = None,
                          name: str = "") -> str:
        """File transfer (upload/download/read, recursive dir mirrors),
        module dumps (VA-layout PE, quiesce/kernel), hashing, listing,
        guarded delete, YARA, tail, tail -f follows, and orchestrator-side
        artifact reads/grep. Per-verb help:
        file_manage(action='actions')."""
        args = {"action": action, "path": path or remote_path, "no_trash": no_trash}

        async def run() -> str:
            # v0.16: list_artifacts and the sha-addressed forms of
            # read_artifact / grep_artifact don't need a live target —
            # they're purely orchestrator-side spill_dir operations. Route
            # them BEFORE require_client() so an unconnected orchestrator
            # can still answer them.
            if action == "list_artifacts":
                from pathlib import Path as _P
                spill_dir = _P(ctx.cfg.spill_dir())
                art_dir = _P(ctx.cfg.artifacts_dir())
                sha_prefix = (sha256 or "").lower().strip()
                kind_filter = (path or "").strip().lower()
                rows: list[dict] = []

                def _spill_row(p: _P) -> dict | None:
                    # spill payloads are named <sha256>.<ext>; the stem IS
                    # the hash, no re-hash needed.
                    ext = p.suffix.lstrip(".").lower()
                    if ext == "idx":
                        return None
                    stem = p.stem.lower()
                    if sha_prefix and not stem.startswith(sha_prefix):
                        return None
                    if kind_filter and ext != kind_filter:
                        return None
                    try:
                        st = p.stat()
                    except OSError:
                        return None
                    return {"sha256": stem, "kind": ext,
                            "size": int(st.st_size),
                            "mtime_ts": st.st_mtime, "path": str(p),
                            "source": "spill"}

                def _store_row(p: _P, source: str) -> dict | None:
                    # dumps/ + ingested/ keep their original filenames; hash
                    # (cached) so about-by-sha and bin_manage path= work
                    # straight after dump_module.
                    if kind_filter and p.suffix.lstrip(".").lower() != kind_filter:
                        return None
                    try:
                        st = p.stat()
                    except OSError:
                        return None
                    digest = _artifact_sha256(p)
                    if sha_prefix and not digest.startswith(sha_prefix):
                        return None
                    try:
                        rel = p.resolve().relative_to(art_dir.resolve())
                        rel_posix = str(rel).replace("\\", "/")
                    except ValueError:
                        rel_posix = p.name
                    return {"sha256": digest,
                            "kind": p.suffix.lstrip(".").lower(),
                            "size": int(st.st_size),
                            "mtime_ts": st.st_mtime,
                            "path": rel_posix, "abs_path": str(p),
                            "source": source}

                seen: set[tuple[str, str]] = set()
                for sub, source in ((spill_dir, "spill"),
                                    (art_dir / "dumps", "dumps"),
                                    (art_dir / "ingested", "ingested")):
                    if not sub.is_dir():
                        continue
                    for p in sub.iterdir():
                        if not p.is_file():
                            continue
                        row = (_spill_row(p) if source == "spill"
                               else _store_row(p, source))
                        if row is None:
                            continue
                        key = (row["sha256"], row["path"])
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append(row)
                rows.sort(key=lambda r: (-r["mtime_ts"], r["sha256"]))
                eff_limit = limit or max_matches
                return _j(_list_envelope(
                    rows, tool="file_manage", action="list_artifacts",
                    kind="artifacts",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"spill_dir": str(spill_dir),
                            "artifacts_dir": str(art_dir),
                            "sources": ["spill", "dumps", "ingested"]},
                ))
            if action == "ingest":
                # v0.21 dev-feedback: copy an arbitrary ORCHESTRATOR-LOCAL
                # file into artifacts/ingested/ so bin_manage / list_artifacts
                # can reach it without shelling a Copy-Item into the sandbox.
                # This is the explicit opt-in hole in the artifacts_dir
                # containment rule — deliberately a separate action, not a
                # bin_manage flag, so the read path stays sandboxed.
                from pathlib import Path as _P
                import shutil as _sh
                src_s = (local_path or "").strip() or (path or "").strip()
                if not src_s:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "ingest: local_path=<absolute local "
                                        "file path> required",
                               "hint": "copies an orchestrator-local file into "
                                       "artifacts/ingested/; analyze it via "
                                       "bin_manage(action='info', path=…)"})
                src_p = _P(src_s).expanduser()
                try:
                    if not src_p.is_file():
                        return _j({"ok": False, "kind": "not_found",
                                   "error": f"ingest: {src_s!r} is not a "
                                            "readable local file"})
                except OSError as exc:
                    return _j({"ok": False, "kind": "not_found",
                               "error": f"ingest: {exc}"})
                digest, _sz = _sha256_file(str(src_p))
                dest_dir = _P(ctx.cfg.artifacts_dir()) / "ingested"
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_name = (module or src_p.name).replace("/", "_").replace("\\", "_")
                dest = dest_dir / dest_name
                if dest.exists():
                    old_digest, _ = _sha256_file(str(dest))
                    if old_digest != digest:
                        dest = dest_dir / f"{src_p.stem}_{digest[:8]}{src_p.suffix}"
                _sh.copy2(src_p, dest)
                rel = dest.resolve().relative_to(
                    _P(ctx.cfg.artifacts_dir()).resolve())
                rel_posix = str(rel).replace("\\", "/")
                return _j({"ok": True, "path": rel_posix,
                           "abs_path": str(dest), "sha256": digest,
                           "size": _sz,
                           "hint": f"bin_manage(action='info', "
                                   f"path='{rel_posix}')"})
            # v0.22: discovery verb — pure compute, before require_client.
            if action == "actions":
                return _actions_help("file_manage", _FILE_ACTION_HELP)
            # grep_artifact + read_artifact never touch the agent — every
            # form of them is orchestrator-side spill_dir work. Skipping
            # require_client() lets an unconnected orchestrator still
            # answer them (matches list_artifacts' behaviour above). Same
            # for read side='orchestrator'.
            c = (None if action in ("read_artifact", "grep_artifact")
                 or (action == "read" and (side or "").lower() == "orchestrator")
                 else ctx.session.require_client(name))
            if action == "upload":
                return _j(await c.file_upload(local_path, remote_path))
            if action == "download":
                if recursive:
                    # v0.25: mirror a remote directory tree into
                    # artifacts/downloads/<sanitized-root>/ preserving
                    # relative layout. ListDir(recursive) returns full
                    # remote paths; per-file failures collect into
                    # `skipped` rather than aborting the walk.
                    import re as _re
                    root = (remote_path or path or "").rstrip("\\/")
                    if not root:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": "download recursive: "
                                            "remote_path=<remote dir> "
                                            "required"})
                    try:
                        entries = await c.file_list_dir(root, recursive=True)
                    except Exception as exc:
                        return _j({"ok": False, **_enrich_error(
                            "file_manage", "download",
                            f"list_dir({root}) failed: {exc}")})
                    files = [e for e in entries if not e.get("dir")]
                    FILE_CAP = 512
                    byte_cap = int(getattr(ctx.cfg.security,
                                           "max_transfer_mb", 512)) \
                        * 1024 * 1024
                    safe_root = _re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_",
                                        root).strip("._") or "root"
                    dest_root = Path(ctx.cfg.artifacts_dir()) / "downloads" \
                        / safe_root
                    downloaded: list[dict] = []
                    skipped: list[dict] = []
                    total_bytes = 0
                    for e in files:
                        if len(downloaded) + len(skipped) >= FILE_CAP:
                            break
                        rname = str(e.get("name") or "")
                        if rname.lower().startswith(root.lower() + "\\") or \
                                rname.lower().startswith(root.lower() + "/"):
                            rel = rname[len(root):].lstrip("\\/")
                        else:
                            rel = _re.split(r"[\\/]+", rname)[-1]
                        segs = [_re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", s)
                                for s in _re.split(r"[\\/]+", rel)
                                if s and s not in (".", "..")]
                        if not segs:
                            skipped.append({"path": rname,
                                            "error": "empty relative path"})
                            continue
                        if total_bytes + int(e.get("size") or 0) > byte_cap:
                            skipped.append({
                                "path": rname,
                                "error": f"total-byte cap "
                                         f"({byte_cap} bytes) reached"})
                            continue
                        dest = dest_root.joinpath(*segs)
                        try:
                            r = await c.file_download(rname, str(dest))
                        except Exception as exc:
                            skipped.append({"path": rname,
                                            "error": str(exc)})
                            continue
                        got = int(r.get("bytes", 0) or 0)
                        total_bytes += got
                        downloaded.append({
                            "path": "/".join(segs), "size": got,
                            "sha256": r.get("sha256", "")})
                    remaining = len(files) - len(downloaded) - len(skipped)
                    out: dict[str, Any] = {
                        "ok": True, "dir": str(dest_root), "root": root,
                        "downloaded": downloaded, "skipped": skipped,
                        "counts": {"listed": len(files),
                                   "downloaded": len(downloaded),
                                   "skipped": len(skipped)},
                        "bytes": total_bytes}
                    if remaining > 0:
                        out["capped"] = True
                        out["remaining"] = remaining
                        out["hint"] = ("tree exceeds the download caps; "
                                       "re-run on a subdir or raise "
                                       "security.max_transfer_mb")
                    return _j(out)
                dest = local_path
                if not dest:
                    dest = ctx.cfg.artifacts_dir() / (path.split("/")[-1] if path else "download.bin")
                return _j(await c.file_download(remote_path or path, str(dest)))
            if action == "read":
                # v0.25: ranged inline read. offset/length ride the
                # Download stream's range fields; the bytes come back in
                # the envelope (hex + ascii preview + optional decode=),
                # NOT into artifacts — a scratch temp file is the staging
                # point because file_download writes to disk.
                import re as _re
                from pathlib import Path as _P
                READ_CAP = 4 * 1024 * 1024
                # v0.28: text-shaped files come back as `text`, not a
                # hex blob to hand-decode. decode= still wins when the
                # caller wants typed values.
                _TEXT_EXTS = {".txt", ".log", ".ps1", ".psm1", ".md",
                              ".cmd", ".bat", ".ini", ".cfg", ".conf",
                              ".json", ".xml", ".yaml", ".yml", ".py",
                              ".c", ".h", ".cs", ".js", ".csv"}
                _TEXT_CAP = 256 * 1024
                off = max(0, int(offset or 0))
                want_len = int(length or 0)

                def _maybe_text(data: bytes, payload: dict) -> None:
                    src = remote_path or path or ""
                    ext = _P(src).suffix.lower() if src else ""
                    if ext not in _TEXT_EXTS:
                        return
                    if len(data) > _TEXT_CAP:
                        payload["text_truncated"] = True
                        payload["text_note"] = (
                            f"text preview capped at {_TEXT_CAP} bytes — "
                            "use offset=/length= ranged reads for the rest")
                        data = data[:_TEXT_CAP]
                    payload["text"] = data.decode("utf-8", errors="replace")

                def _finish_read(data: bytes, payload: dict) -> Any:
                    payload["size"] = len(data)
                    payload["hex"] = data.hex()
                    payload["ascii"] = _ascii(data)
                    _maybe_text(data, payload)
                    if decode:
                        from ..conversions import decode_buffer as _d_buf
                        from ..conversions import ConversionError as _CvE
                        try:
                            decoded = _d_buf(data, decode)
                        except _CvE as exc:
                            return _j({"ok": False, "kind": exc.kind,
                                       "error": str(exc),
                                       "hint": getattr(exc, "hint", "")})
                        payload["values"] = decoded["values"]
                        payload["layout"] = decoded["layout"]
                        if decoded.get("truncated"):
                            payload["truncated"] = True
                        if decoded.get("remainder_hex"):
                            payload["remainder_hex"] = \
                                decoded["remainder_hex"]
                    return _j(payload)

                if (side or "").lower() == "orchestrator":
                    # read_artifact semantics: a bare 64-hex sha256 (or the
                    # sha256 kwarg) resolves into spill_dir; a path is
                    # contained to artifacts_dir / spill_dir like
                    # grep_artifact. No target contact.
                    target = remote_path or path or local_path
                    sha_val = sha256 or (
                        target if _re.fullmatch(r"[0-9a-fA-F]{64}",
                                                target or "") else "")
                    if sha_val:
                        from .._spill import read_slice as _read_slice
                        try:
                            return _j(_read_slice(
                                sha_val.lower(), ctx.cfg.spill_dir(),
                                offset=off, length=want_len))
                        except FileNotFoundError:
                            # v0.27: whole-store lookup — dumps/ingested
                            # payloads carry their content sha too, not
                            # just spill/.
                            from .._artifacts import find_artifact_by_sha
                            hit = find_artifact_by_sha(ctx.cfg, sha_val)
                            if hit is None:
                                return _j({
                                    "ok": False,
                                    "kind": "artifact_missing",
                                    "error": f"no artifact with sha256 "
                                             f"{sha_val[:12]}... in "
                                             "spill/, dumps/, or "
                                             "ingested/",
                                    "hint": "file_manage(action="
                                            "'list_artifacts') to see "
                                            "what's on disk"})
                            return _j(_read_slice(
                                hit[1], ctx.cfg.spill_dir(),
                                offset=off, length=want_len,
                                path=_P(hit[0])))
                        except ValueError as exc:
                            return _j({"ok": False, "kind": "bad_arg",
                                       "error": str(exc)})
                    if not target:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": "read side='orchestrator': "
                                            "pass sha256= or remote_path="
                                            "<file under artifacts/>"})
                    from .._artifacts import resolve_artifact_path
                    p = resolve_artifact_path(ctx.cfg, target)
                    if p is None:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": f"read side='orchestrator': "
                                            f"{target!r} is outside "
                                            "artifacts_dir",
                                   "hint": "orchestrator-side reads are "
                                           "limited to files under "
                                           "artifacts/ (or the spill "
                                           "dir); pass sha256 for spill "
                                           "artifacts"})
                    if not p.is_file():
                        return _j({"ok": False, "kind": "not_found",
                                   "error": f"read side='orchestrator': "
                                            f"{target!r} is not a file"})
                    total = p.stat().st_size
                    want = min(want_len if want_len > 0 else total - off,
                               total - off, READ_CAP)
                    with p.open("rb") as fh:
                        fh.seek(off)
                        data = fh.read(max(0, want))
                    payload: dict[str, Any] = {
                        "path": str(p), "offset": off, "side": "orchestrator",
                        "total_size": total,
                        "sha256": _artifact_sha256(p)}
                    if off + len(data) < total:
                        payload["truncated"] = True
                        payload["next_offset"] = off + len(data)
                    return _finish_read(data, payload)

                target = remote_path or path
                if not target:
                    from .._envelope.build import sanitize_received_args
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "file_manage read: remote_path/path "
                                        "arrived empty — if you sent one, "
                                        "the param was stripped in transit",
                               "received_args": sanitize_received_args({
                                   "remote_path": remote_path, "path": path,
                                   "offset": offset, "length": length,
                                   "action": action}),
                               "hint": "e.g. remote_path=r'C:\\Temp\\x.bin' "
                                       "with offset=/length= for a ranged "
                                       "read; side='orchestrator' reads a "
                                       "local artifact instead"})
                # length=0 means "to EOF" — probe the size so the inline
                # cap stays honest; when the probe fails the cap still
                # bounds what we pull.
                total = 0
                if want_len > 0:
                    want = min(want_len, READ_CAP)
                else:
                    want = READ_CAP
                    try:
                        meta = await c.file_hash(target)
                        total = int(meta.get("size", 0) or 0)
                    except Exception:
                        total = 0
                    if total:
                        want = min(max(total - off, 0), READ_CAP)
                dl: dict[str, Any] = {}
                if want <= 0:
                    data = b""
                else:
                    import tempfile as _tf
                    fd, tmp = _tf.mkstemp(prefix="suspex_read_",
                                          suffix=".bin")
                    os.close(fd)
                    try:
                        dl = await c.file_download(target, tmp,
                                                   offset=off,
                                                   length=want)
                        data = _P(tmp).read_bytes()
                    finally:
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass
                payload = {"path": target, "offset": off,
                           "side": "target"}
                if total:
                    payload["total_size"] = total
                    if off + len(data) < total:
                        payload["truncated"] = True
                        payload["next_offset"] = off + len(data)
                elif want_len > READ_CAP:
                    payload["truncated"] = True
                    payload["next_offset"] = off + len(data)
                if dl.get("sha256"):
                    payload["sha256"] = dl["sha256"]
                if dl.get("via_snapshot"):
                    payload["via_snapshot"] = True
                    payload["note"] = dl.get("note", "")
                return _finish_read(data, payload)
            if action == "dump_module":
                if kernel:
                    guard = await _require_driver(ctx, "file_manage",
                                                  "dump_module", name)
                    if guard: return _j(guard)
                dest = local_path
                if not dest:
                    base_name = module.replace("\\", "/").split("/")[-1] or "module.bin"
                    if "." not in base_name:
                        base_name += ".dll"
                    dest = str(ctx.cfg.artifacts_dir() / "dumps" / base_name)
                result = await c.file_dump_module(pid, module, str(dest),
                                                  quiesce=quiesce, dump_type=dump_type,
                                                  kernel=kernel)
                result["ida_hint"] = ("open via ida_manage(action='open', path='" + str(dest) + "')")
                # v0.24: per-section residency — incomplete sections are
                # named explicitly so a grep over zeroed PAGE/INIT bytes
                # can't be misread as "the section is empty".
                incomplete = [s["name"] for s in result.get("sections", [])
                              if not s.get("complete")]
                if incomplete:
                    result["warnings"] = [
                        "partial sections (tail reads as zeros): "
                        + ", ".join(incomplete)]
                # v0.18 auto-breadcrumb: register the dumped binary in the KB
                # so a peer's about(alias=module) will surface this dump. Best
                # effort — a hashing/DB failure never fails the dump itself.
                try:
                    _register_dumped_module(ctx, dest, module, kernel)
                except Exception as _exc:  # pragma: no cover - defensive
                    log.debug("dump_module breadcrumb dropped: %s", _exc)
                return _j(result)
            if action == "hash":
                return _j(await c.file_hash(remote_path or path))
            if action == "tail":
                target = remote_path or path
                if not target:
                    from .._envelope.build import sanitize_received_args
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "file_manage tail: remote_path/path "
                                        "arrived empty — if you sent one, "
                                        "the param was stripped in transit",
                               "received_args": sanitize_received_args({
                                   "remote_path": remote_path, "path": path,
                                   "bytes": bytes, "action": action}),
                               "hint": "e.g. remote_path=r'C:\\Users\\Public\\Desktop\\suspex_kernel.log'"})
                return _j(await c.file_tail(target, bytes_wanted=int(bytes),
                                            line_align=line_align))
            if action == "follow_start":
                return _j(await _follow_start(
                    ctx, c, remote_path or path,
                    from_offset=from_offset,
                    initial_tail_bytes=initial_tail_bytes,
                    poll_interval_ms=poll_interval_ms,
                    max_chunk_bytes=max_chunk_bytes,
                    line_align=line_align,
                    follow_rotation=follow_rotation,
                    duration_s=duration_s,
                    max_bytes=max_bytes,
                    ring_cap=ring_cap))
            if action == "follow_poll":
                return _j(_follow_poll(ctx, follow_id, from_seq=from_seq))
            if action == "follow_stop":
                return _j(await _follow_stop(ctx, follow_id))
            if action == "follow_list":
                return _j(_follow_list(ctx))
            if action == "list_dir":
                # NOTE: this walks the REMOTE target VM's filesystem via the
                # agent's file_list_dir RPC — NOT the orchestrator-side
                # artifacts directory. For orchestrator-side artifacts
                # (auto-spilled tool responses) use
                # file_manage(action='list_artifacts') instead.
                return _j({"entries": await c.file_list_dir(path, recursive)})
            if action == "delete":
                return _j(await c.file_delete(path, no_trash))
            if action == "grep_artifact":
                import re as _re
                from pathlib import Path as _P
                target = local_path or path or remote_path or sha256
                if not target or not pattern:
                    return _j({"ok": False,
                                "error": "grep_artifact: path + pattern required",
                                "hint": "path is an ORCHESTRATOR-SIDE artifact path "
                                        "(under artifacts/) OR a bare 64-char sha256 "
                                        "for a spilled artifact; pattern is a Python regex"})
                # v0.16: accept a bare 64-hex sha256 and resolve it to the
                # spilled artifact path via the same helper `read_artifact`
                # uses. Falls through to the existing path-resolution logic
                # for actual filesystem paths.
                p = None
                if isinstance(target, str) and _re.fullmatch(r"[0-9a-fA-F]{64}", target):
                    try:
                        from .._spill import _resolve_by_sha
                        p = _resolve_by_sha(target.lower(), ctx.cfg.spill_dir())
                    except FileNotFoundError:
                        # v0.27: whole-store lookup — a dumps/ingested
                        # artifact is greppable by content sha too.
                        from .._artifacts import find_artifact_by_sha
                        hit = find_artifact_by_sha(ctx.cfg, target)
                        if hit is None:
                            return _j({"ok": False, "kind": "artifact_missing",
                                        "error": f"grep_artifact: no artifact for "
                                                 f"sha256 {target[:12]}...",
                                        "hint": "file_manage(action='list_artifacts') to "
                                                "see what's on disk"})
                        p = _P(hit[0])
                    except ValueError as exc:
                        return _j({"ok": False, "kind": "bad_arg",
                                    "error": f"grep_artifact: {exc}"})
                if p is None:
                    from .._artifacts import resolve_artifact_path
                    p = resolve_artifact_path(ctx.cfg, target)
                    if p is None:
                        return _j({"ok": False,
                                    "error": f"grep_artifact: {target!r} is outside artifacts_dir",
                                    "hint": "server-side grep is limited to files under "
                                            "artifacts/ (or the configured spill dir); "
                                            "use a bare 64-char sha256 to reach a "
                                            "spilled response artifact"})
                if not p.exists():
                    return _j({"ok": False, "error": f"file not found: {target}"})
                try:
                    pat = _re.compile(pattern)
                except _re.error as exc:
                    return _j({"ok": False, "error": f"bad regex: {exc}"})
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    return _j({"ok": False, "error": f"read failed: {exc}"})
                lines = text.splitlines()
                hits = []
                for i, line in enumerate(lines):
                    if pat.search(line):
                        lo = max(0, i - int(context))
                        hi = min(len(lines), i + int(context) + 1)
                        hits.append({
                            "line": i + 1,
                            "match": line,
                            "context": lines[lo:hi],
                            "context_start_line": lo + 1,
                        })
                # v0.14 Layer 3: unified list envelope. `max_matches` aliases
                # to `limit`; slicing/filter/summary flow through apply_page_opts.
                eff_limit = limit or max_matches
                return _j(_list_envelope(
                    hits, tool="file_manage", action="grep_artifact",
                    kind="grep",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"path": str(p), "pattern": pattern},
                ))
            if action == "read_artifact":
                # v0.14 auto-spill: fetch a spilled response payload back.
                # Dispatch on the on-disk extension so callers never have
                # to know which helper (bytes / rows / listing pages) to
                # request; the artifact's `content_type` in the envelope
                # already tells them, but the extension is authoritative.
                from .._spill import (
                    read_slice as _read_slice,
                    read_rows as _read_rows,
                    read_listing_page as _read_listing_page,
                )
                if not sha256:
                    from .._envelope.build import sanitize_received_args
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "read_artifact: sha256 arrived empty — "
                                        "if you sent one, the param was "
                                        "stripped in transit",
                               "received_args": sanitize_received_args({
                                   "sha256": sha256, "offset": offset,
                                   "length": length, "action": action}),
                               "hint": "the sha256 lives in env.artifact.sha256 "
                                       "of the response that spilled"})
                spill_dir = ctx.cfg.spill_dir()
                try:
                    sha_lower = sha256.lower()
                    if (spill_dir / f"{sha_lower}.listing").exists():
                        return _j(_read_listing_page(sha256, spill_dir,
                                                     page=page,
                                                     page_size=page_size))
                    if (spill_dir / f"{sha_lower}.jsonl").exists():
                        return _j(_read_rows(sha256, spill_dir,
                                             page=page, page_size=page_size))
                    # Any remaining suffix (.bin, .txt, .json) — byte-range read.
                    return _j(_read_slice(sha256, spill_dir,
                                          offset=offset, length=length))
                except FileNotFoundError:
                    # v0.27: the caller may hold a dumps/ingested artifact's
                    # sha — the store index covers those too, not just spill/.
                    from .._artifacts import find_artifact_by_sha
                    hit = find_artifact_by_sha(ctx.cfg, sha256)
                    if hit is None:
                        return _j({"ok": False, "kind": "artifact_missing",
                                   "error": f"read_artifact: no artifact for "
                                            f"sha256 {sha256[:12]}...",
                                   "hint": "the artifact expired or was never "
                                           "spilled; re-run the source tool, "
                                           "or file_manage(action="
                                           "'list_artifacts') to browse"})
                    return _j(_read_slice(hit[1], spill_dir,
                                          offset=offset, length=length,
                                          path=Path(hit[0])))
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
            if action == "yara":
                from ...yara import yara_available, yara_scan_file, yara_scan_remote_file

                if not yara_available():
                    return _j({"ok": False,
                               "error": "yara-python not installed (pip install suspex0[yara])"})
                rule_src = rule
                if not rule_src and rule_path:
                    from pathlib import Path as _P
                    rule_src = _P(rule_path).read_text(encoding="utf-8")
                if not rule_src:
                    return _j({"ok": False, "error": "yara requires 'rule' or 'rule_path'"})
                matches, scan_error = await yara_scan_remote_file(c, remote_path or path,
                                                                  rule_src,
                                                                  ctx.cfg.artifacts_dir())
                if scan_error:
                    return _j({"ok": False, "error": scan_error})
                cid = current_client_id()
                sid = ctx.get_current_session_id(cid) or ctx.ledger.start_session(
                    ctx.session.cfg.target_endpoint)
                if not ctx.get_current_session_id(cid):
                    ctx.set_current_session_id(cid, sid)
                fid = ctx.ledger.record(sid, "warning" if matches else "info",
                                        f"yara: {remote_path or path}",
                                        f"{len(matches)} rule match(es)",
                                        agent_id=cid)
                ctx.ledger.add_evidence(fid, "yara_matches", _j(matches))
                return _j({"ok": True, "matches": matches, "finding_id": fid})
            return _unknown_action("file_manage", action, FILE_ACTIONS, _FILE_ACTION_HELP)

        return await _guard(ctx, "file_manage", action, args, run)
