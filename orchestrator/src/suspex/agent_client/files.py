"""Files-service methods split off from AgentClient."""

from __future__ import annotations

import time
from typing import Any

from ..caller import current_client_id
from ..generated import suspex_pb2 as pb
from .wire import proto_to_dict, status_dict


class FilesMixin:
    # ----------------------------------------------------------------- Files ----

    async def file_upload(self, local_path: str, remote_path: str) -> dict[str, Any]:
        import hashlib
        from pathlib import Path

        data = Path(local_path).read_bytes()
        async def gen():
            hdr = pb.UploadChunk(header=pb.UploadHeader(path=remote_path, size=len(data)))
            yield hdr
            for off in range(0, len(data), 64 * 1024):
                yield pb.UploadChunk(data=data[off : off + 64 * 1024])

        msg = await self.files.Upload(gen(), metadata=self._meta(), timeout=self._timeout)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error,
            "sha256": msg.sha256,
            "bytes_written": msg.bytes_written,
            "local_sha256": hashlib.sha256(data).hexdigest(),
        }

    async def file_download(self, remote_path: str, local_path: str, offset: int = 0,
                            length: int = 0) -> dict[str, Any]:
        import hashlib
        from pathlib import Path

        sha = hashlib.sha256()
        total = 0
        via_snapshot = False
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as fh:  # truncate: re-downloads must not append
            async for chunk in self.files.Download(
                pb.DownloadRequest(path=remote_path, offset=offset, length=length),
                metadata=self._meta(),
            ):
                which = chunk.WhichOneof("payload")
                if which == "header":
                    # v14: share-mode-0 live file → bytes came from a VSS
                    # shadow copy. Point-in-time, may lag a live writer.
                    via_snapshot = bool(getattr(chunk.header, "via_snapshot", False))
                elif which == "data":
                    fh.write(chunk.data)
                    sha.update(chunk.data)
                    total += len(chunk.data)
        out = {"path": local_path, "bytes": total, "sha256": sha.hexdigest(),
               "via_snapshot": via_snapshot}
        if via_snapshot:
            out["note"] = ("downloaded bytes are a VSS shadow copy — the live "
                           "file is share-mode-0 locked and may have changed "
                           "since the snapshot")
        return out

    async def file_dump_module(self, pid: int, module: str, local_path: str,
                               quiesce: bool = False, dump_type: str = "as_loaded",
                               kernel: bool = False) -> dict[str, Any]:
        import hashlib
        from pathlib import Path

        sha = hashlib.sha256()
        total = 0
        notes = ""
        sections: list[dict[str, Any]] = []
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        buf = bytearray()
        async for chunk in self.files.DumpModule(
            pb.DumpModuleRequest(pid=pid, module=module, quiesce=quiesce,
                                 dump_type=dump_type, kernel=kernel),
            metadata=self._meta(),
        ):
            which = chunk.WhichOneof("payload")
            if which == "header":
                notes = chunk.header.notes
                # v0.24: per-section residency map from the dumper.
                sections = [
                    {"name": s.name, "va": s.va, "size": s.size,
                     "dumped_bytes": s.dumped_bytes, "complete": s.complete}
                    for s in chunk.header.sections
                ]
            elif which == "data":
                buf.extend(chunk.data)
                total += len(chunk.data)
        Path(local_path).write_bytes(buf)
        sha.update(bytes(buf))
        return {"path": local_path, "bytes": total, "sha256": sha.hexdigest(),
                "notes": notes, "sections": sections}

    async def file_hash(self, remote_path: str) -> dict[str, Any]:
        msg = await self._call(self.files.Hash, pb.HashRequest(path=remote_path))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"sha256": msg.sha256, "size": msg.size,
                "via_snapshot": bool(getattr(msg, "via_snapshot", False))}

    async def file_tail(self, remote_path: str, bytes_wanted: int = 65536,
                        line_align: bool = True) -> dict[str, Any]:
        """Return the last N bytes of a remote file.

        Phase 0 implementation: `file_hash` for size, then Download with
        `offset=max(0, size - bytes_wanted)`. Phase 1 will short-circuit to
        the new `Files.LogTail` RPC when the agent supports it — the return
        shape stays the same so callers don't care.
        """
        # Prefer the native Files.LogTail RPC when the agent supports it.
        if hasattr(self.files, "LogTail"):
            try:
                msg = await self._call(
                    self.files.LogTail,
                    pb.LogTailRequest(path=remote_path, bytes=bytes_wanted,
                                      line_align=line_align, include_rotated=False),
                )
                if msg.status.ok:
                    return {"path": remote_path,
                            "data": msg.data.decode("utf-8", "replace"),
                            "bytes": len(msg.data),
                            "total_size": msg.total_size,
                            "tail_offset": msg.tail_offset,
                            "truncated": msg.truncated,
                            "via_snapshot": bool(getattr(msg, "via_snapshot", False)),
                            "backend": "log_tail"}
            except Exception:
                # Fall back to chunked download if the RPC path errors.
                pass
        # Fallback: hash-for-size + range download.
        try:
            meta = await self.file_hash(remote_path)
        except Exception as exc:
            err = str(exc)
            low = err.lower()
            # v14: classify the agent's Win32 error instead of the old
            # catch-all "check the path exists" — which claimed an existing
            # locked file was missing. gle=32/gle=33 = share violation;
            # gle=5 = access denied; gle=2/3 = actually missing.
            if "gle=32" in low or "gle=33" in low or "sharing" in low or \
                    "0xc0000043" in low:
                hint = ("file exists but is share-mode-0 locked — metadata "
                        "still works; a v14+ agent falls back to a VSS "
                        "shadow copy for content, and follow_start reports "
                        "growth via stat events until the writer unlocks")
            elif "gle=5" in low or "denied" in low:
                hint = "access denied on open — try kernel=true paths or an elevated agent"
            elif "gle=2" in low or "gle=3" in low or "cannot stat" in low:
                hint = "check the path exists on the target"
            else:
                hint = ("stat succeeded but hash/read failed — see error "
                        "for the Win32 code")
            return {"ok": False,
                    "error": f"file_tail: stat/hash probe failed: {err}",
                    "hint": hint}
        total = int(meta.get("size", 0))
        want = min(int(bytes_wanted), total)
        offset = max(0, total - want)
        buf = bytearray()
        via_snapshot = False
        async for chunk in self.files.Download(
            pb.DownloadRequest(path=remote_path, offset=offset, length=want),
            metadata=self._meta(),
        ):
            which = chunk.WhichOneof("payload")
            if which == "header":
                via_snapshot = bool(getattr(chunk.header, "via_snapshot", False))
            elif which == "data":
                buf.extend(chunk.data)
        text = bytes(buf).decode("utf-8", "replace")
        if line_align and len(text) < total and "\n" in text:
            # Skip the first (possibly partial) line so the tail is line-clean.
            text = text.split("\n", 1)[1] if "\n" in text else text
        return {"path": remote_path, "data": text, "bytes": len(buf),
                "total_size": total, "tail_offset": offset,
                "truncated": offset > 0, "backend": "download_range",
                "via_snapshot": via_snapshot or bool(meta.get("via_snapshot"))}

    async def file_list_dir(self, path: str, recursive: bool = False, max_entries: int = 2000) -> list[dict[str, Any]]:
        msg = await self._call(
            self.files.ListDir, pb.ListDirRequest(path=path, recursive=recursive, max_entries=max_entries)
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def file_delete(self, path: str, no_trash: bool = False) -> dict[str, Any]:
        st = await self._call(self.files.Delete, pb.DeleteRequest(path=path, no_trash=no_trash))
        return status_dict(st)

    # v8: streaming tail-f. The gRPC stream is driven from the orchestrator side
    # (this is an async iterator over LogFollowChunk); the MCP tool feeds chunks
    # into a bounded per-follow_id ring the LLM polls. Returns None if the agent
    # predates v8 and the RPC isn't wired up (caller falls back to LogTail).
    async def log_follow_iter(self, path: str, *,
                              from_offset: int = 0,
                              initial_tail_bytes: int = 65536,
                              poll_interval_ms: int = 200,
                              max_chunk_bytes: int = 65536,
                              line_align: bool = True,
                              follow_rotation: bool = True,
                              duration_s: int = 600,
                              max_bytes: int = 0):
        """Async generator yielding LogFollowChunk messages until the stream ends.

        The agent stamps ok=true on the first chunk and eof=true on the terminal
        chunk (with `reason` populated). We yield every chunk including the
        terminal one so the caller can surface `reason` cleanly.
        """
        if not hasattr(self.files, "LogFollow"):
            return
        req = pb.LogFollowRequest(
            path=path,
            from_offset=from_offset,
            initial_tail_bytes=initial_tail_bytes,
            poll_interval_ms=poll_interval_ms,
            max_chunk_bytes=max_chunk_bytes,
            line_align=line_align,
            follow_rotation=follow_rotation,
            duration_s=duration_s,
            max_bytes=max_bytes,
        )
        # LogFollow is server-streaming: use the raw stub (not _call, whose
        # semaphore/ring is for unary calls). We still record a compact entry
        # so recent_ops() shows the follow started.
        entry = {
            "t_start": time.time(),
            "method": "files.LogFollow",
            "req_summary": {"path": path, "from_offset": from_offset,
                            "duration_s": duration_s},
            "status": "streaming",
            "client_id": current_client_id(),
        }
        self._recent_ops.append(entry)
        if len(self._recent_ops) > self._RING_CAP:
            del self._recent_ops[: len(self._recent_ops) - self._RING_CAP]
        try:
            async for chunk in self.files.LogFollow(req, metadata=self._meta()):
                self._last_seen_ts = time.time()
                yield chunk
            entry["status"] = "ok"
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            entry["t_end"] = time.time()
            entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)
