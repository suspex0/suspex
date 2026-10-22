"""Facade for the `suspex.agent_client` package (mechanical split of the
former agent_client.py). Re-exports the public surface callers rely on:
AgentClient, Event, EventBus, and the wire helpers (proto_to_dict,
status_dict, envelope, _summarize_req)."""

from __future__ import annotations

from .client import AgentClient
from .events import Event, EventBus
from .wire import _summarize_req, envelope, proto_to_dict, status_dict

__all__ = [
    "AgentClient",
    "Event",
    "EventBus",
    "envelope",
    "proto_to_dict",
    "status_dict",
    "_summarize_req",
]
