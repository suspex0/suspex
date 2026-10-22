"""Static binary-analysis passes for suspex0 — the knife-derived engine.

Everything in this package is pure orchestrator-side compute over a byte
image: no target contact, no agent RPC. The MCP surface that exposes it
is ``bin_manage`` (``mcp/tools/bin.py``); live-memory extraction reuses the
same primitives through ``mem_rw strings`` / ``mem_rw entropy``.

Design rules (carried over from knife):

* Bounded work on untrusted input — every table walk has an entry cap,
  every scan a byte cap, and truncation is always reported rather than
  silently producing partial results.
* Evidence-honest reporting — a pass that cannot prove reachability says
  ``Unresolved``, never ``unreachable`` (see ``reachability.py``).
* No new hard dependencies — the PE parser is hand-rolled (``pe.py``),
  matching the ``sdk/pe.py`` precedent. Disassembly uses the existing
  ``codegen`` extra (capstone) through a soft import.
"""
