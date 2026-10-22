"""Proto <-> dict wire helpers for the agent client."""

from __future__ import annotations

from typing import Any

from ..generated import suspex_pb2 as pb


def status_dict(st: pb.OpStatus) -> dict[str, Any]:
    return {"ok": st.ok, "error": st.error, "errno_code": st.errno_code}


def envelope(msg: Any, keys: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": msg.status.ok, "error": msg.status.error}
    for key in keys:
        v = getattr(msg, key)
        if isinstance(v, (int, float, str, bytes, bool)):
            out[key] = v
        elif hasattr(v, "SerializeToString"):
            out[key] = proto_to_dict(v)
    return out


def proto_to_dict(msg: Any) -> dict[str, Any]:
    from google.protobuf.json_format import MessageToDict

    # including_default_value_fields=True: without it, MessageToDict OMITS
    # any proto3 field at its default value, so a DebugEvent whose enum kind
    # is BREAKPOINT_SW (=0) comes back with no `kind` at all. Downstream
    # code then can't tell a bp hit from a random event.
    try:
        d = MessageToDict(msg, preserving_proto_field_name=True,
                          including_default_value_fields=True)
    except TypeError:
        # newer protobuf renamed the flag
        d = MessageToDict(msg, preserving_proto_field_name=True,
                          always_print_fields_with_no_presence=True)
    d.pop("status", None)
    return d


def _summarize_req(req: Any) -> dict[str, Any]:
    """Compact request preview for the recent-ops ring: pick short scalar
    fields (address, pid, size, path) and skip large blobs (bytes, streams)."""
    if req is None:
        return {}
    out: dict[str, Any] = {"type": type(req).__name__}
    for name in ("pid", "address", "size", "space", "path", "module",
                 "remote_path", "local_path", "kind", "slot", "kernel"):
        if hasattr(req, name):
            v = getattr(req, name)
            if isinstance(v, (bool, int, str)) and (not isinstance(v, str)
                                                    or len(v) <= 200):
                if isinstance(v, int) and name in ("address", "base"):
                    out[name] = hex(v)
                else:
                    out[name] = v
    return out
