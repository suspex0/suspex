"""Screen tool registration for the suspex0 MCP server — v15.

``screen_manage`` is the visual-inspection surface of the target:

- ``capture`` — desktop (DXGI duplication) or window (WGC) screenshot as PNG.
  Bytes land under ``artifacts/screenshots/``; the envelope carries the path,
  dimensions, sha256 and (opt-in) inline base64. Pillow scales to
  ``max_dimension`` when importable; without it the raw agent PNG passes
  through untouched.
- ``windows`` — Z-ordered window list grouped by process with full per-window
  metadata (class, style/exstyle, status, rects, placement, owner/parent,
  pid/tid, process path, hinstance, flags, DPI). ``include_hidden=True`` opts
  into invisible/cloaked/untitled windows (default: visible only).
- ``displays`` — attached monitor topology.

All three funnel through the session-1 worker on the target (a Session-0
service cannot see the user desktop), so they require a connected target view.
"""

from __future__ import annotations

import base64

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

SCREEN_ACTIONS = ["capture", "windows", "displays", "actions"]

SCREENSHOT_SUBDIR = "screenshots"

_SCREEN_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "screen_manage(action='actions')"},
    "capture": {"one_liner": "screenshot the desktop or one window (PNG)",
                "key_args": "mode, display_id, hwnd, pid, window_title, "
                            "process_name, max_dimension, embed, "
                            "include_hidden, include_details",
                "example": "screen_manage(action='capture', pid=4812)"},
    "windows": {"one_liner": "enumerate windows grouped by process with "
                             "full metadata (class, style/exstyle, status, "
                             "rects, placement, z-order, pid/tid, flags, "
                             "dpi)",
                "key_args": "pid, process_name, query, include_hidden, "
                            "include_details",
                "example": "screen_manage(action='windows', "
                           "include_hidden=True)"},
    "displays": {"one_liner": "list attached displays (device name, "
                              "primary, active, rects)",
                 "key_args": "none",
                 "example": "screen_manage(action='displays')"},
}


def _scale_and_compress(raw: bytes, max_dim: int) -> tuple[bytes, int, int]:
    """Aspect-ratio preserving bounding-box clamp, PNG re-encode.

    Returns (png_bytes, width, height). Without Pillow (not importable) the
    raw agent PNG passes through with its native size untouched.
    """
    try:
        import io

        from PIL import Image
    except Exception:
        return raw, 0, 0
    img = Image.open(io.BytesIO(raw))
    orig_w, orig_h = img.size
    largest = max(orig_w, orig_h)
    if largest > max_dim:
        s = max_dim / float(largest)
        img = img.resize((max(1, round(orig_w * s)), max(1, round(orig_h * s))),
                         Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue(), img.width, img.height


def _parse_windows_json(res: dict) -> dict:
    """Telemetry arrives as raw JSON from the session-1 worker; parse it
    defensively — a truncated/empty blob degrades to an empty list, never an
    exception (the pixels are still deliverable)."""
    raw = res.get("windows_json") or "{}"
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def register(mcp, ctx: Context) -> None:
    """Register the ``screen_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def screen_manage(action: Annotated[str, Field(json_schema_extra={"enum": SCREEN_ACTIONS})],
                            mode: str = "desktop",
                            display_id: str = "",
                            hwnd: str = "",
                            pid: int = 0,
                            window_title: str = "",
                            process_name: str = "",
                            query: str = "",
                            max_dimension: int = 1920,
                            include_hidden: bool = False,
                            include_details: bool = True,
                            embed: bool = False,
                            name: str = "") -> str:
        """Visual screen inspection of the target: capture screenshots
        (desktop via DXGI, window via WGC) for multimodal analysis, enumerate
        windows grouped by process with full metadata (class, style/exstyle,
        status, rects, placement, z-order, pid/tid, flags, dpi —
        include_hidden=True also lists hidden windows), and inspect display
        topology. Everything runs in the target's interactive session; a
        locked/logged-off box answers with an explicit error. Per-verb help:
        screen_manage(action='actions')."""
        args = {"action": action, "mode": mode, "name": name}

        async def run() -> str:
            if action == "actions":
                return _actions_help("screen_manage", _SCREEN_ACTION_HELP)

            c = ctx.session.require_client(name)

            if action == "windows":
                res = await c.list_windows(pid=pid, process_name=process_name,
                                           query=query,
                                           include_hidden=include_hidden,
                                           include_details=include_details)
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "list_windows_failed"})
                data = _parse_windows_json(res)
                procs = data.get("processes") or []
                total = sum(len(g.get("windows") or []) for g in procs)
                return _j({"ok": True, "kind": "windows",
                           "total_windows": total,
                           "include_hidden": include_hidden,
                           "include_details": include_details,
                           "processes": procs})

            if action == "displays":
                res = await c.capture_screen(mode="displays")
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "displays_failed"})
                data = _parse_windows_json(res)
                return _j({"ok": True, "kind": "displays",
                           "displays": data.get("displays") or []})

            if action == "capture":
                hwnd_val = int(hwnd, 0) if hwnd else 0
                # process_name also selects window mode (worker resolves the
                # topmost visible window of that exe).
                capture_mode = ("window" if (hwnd_val or pid or window_title
                                             or process_name) else "desktop")
                res = await c.capture_screen(
                    mode=capture_mode, display_id=display_id, hwnd=hwnd_val,
                    pid=pid, window_title=window_title,
                    process_name=process_name, query=query,
                    include_hidden=include_hidden,
                    include_details=include_details)
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "capture_failed"})

                raw = res.get("image_data") or b""
                if not raw:
                    return _j({"ok": False, "kind": "error",
                               "error": "capture: empty image payload"})
                scaled, w, h = _scale_and_compress(raw, max(1, int(max_dimension)))
                if not w:   # Pillow unavailable: keep native agent dims
                    w, h = int(res.get("width") or 0), int(res.get("height") or 0)

                from datetime import datetime
                now = datetime.now().strftime("%Y%m%d_%H%M%S")
                if pid:
                    target = f"pid_{pid}"
                elif hwnd_val:
                    target = f"hwnd_{hwnd_val:x}"
                elif display_id:
                    target = display_id
                else:
                    target = "primary"
                art_dir = Path(ctx.cfg.artifacts_dir()) / SCREENSHOT_SUBDIR
                art_dir.mkdir(parents=True, exist_ok=True)
                art_path = art_dir / f"screen_{target}_{now}.png"
                art_path.write_bytes(scaled)

                env: dict = {
                    "ok": True,
                    "kind": "screenshot",
                    "capture_mode": capture_mode,
                    "target_type": res.get("target_type") or capture_mode,
                    "target_name": res.get("target_name") or "",
                    "width": w,
                    "height": h,
                    "size_bytes": len(scaled),
                    "sha256": hashlib.sha256(scaled).hexdigest(),
                    "artifact_path": str(art_path),
                    "filename": art_path.name,
                    "scaled": bool(w and (w != int(res.get("width") or 0))),
                }
                if embed:
                    env["image_base64"] = base64.b64encode(scaled).decode("ascii")
                # Window telemetry always rides along when the worker sent it.
                data = _parse_windows_json(res)
                procs = data.get("processes") or []
                if procs:
                    env["total_windows"] = sum(len(g.get("windows") or [])
                                               for g in procs)
                    env["processes"] = procs
                return _j(env)

            return _unknown_action("screen_manage", action, SCREEN_ACTIONS,
                                   _SCREEN_ACTION_HELP)

        return await _guard(ctx, "screen_manage", action, args, run)
