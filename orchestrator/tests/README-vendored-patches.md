# Vendored plugin patches

Some fixes we ship live inside the vendored ida-pro-mcp plugin at
`orchestrator/.ida-mcp-venv/Lib/site-packages/ida_pro_mcp/mcp-plugin.py`
rather than in first-party code. This file records those patches so
they survive a re-install / venv rebuild.

Re-apply this list any time the ida-pro-mcp package is bumped.

## v0.17 D-1/D-2/D-3 — shim-side response transformers (no vendored edit)

The v0.17 plan sketches three vendored-plugin patches:

* `get_xrefs_to` — group by containing function, project ``fields=[...]``.
* `analyze_struct_detailed` — compact default with ``detail=false`` /
  ``members=[<name>...]``.
* `decompile_function` — annotations toggle + ``around_address`` +
  ``max_bytes`` windowing.

Rather than patching the vendored `mcp-plugin.py` directly (which forces a
re-apply after every `pip install ida-pro-mcp --upgrade`), the transforms
land as **client-side transformers** in `orchestrator/idalib_stdio_shim.py`
that pull the new knobs off `args` before the backend call and reshape the
raw response before it reaches the MCP caller. Nothing needs re-applying
after an ida-pro-mcp upgrade; the transformers key off tool name and tool
response shape only.

The pure logic lives in `orchestrator/ida_shim_ergo.py`:

* `group_xrefs(raw, target_ea, group_by_function, fields)`
* `compact_analyze_struct(raw, name, detail, members)`
* `apply_decompile_window(text, annotations, around_address,
  window_lines, max_bytes)`

Tests under `orchestrator/tests/test_d_[1-3]_*.py` round-trip a synthetic
raw response through each transformer without booting the IDA runtime.

If a future upstream release adds these knobs to the backend directly,
delete this section and drop the shim-side transformer wire-in.

## v0.16 — `get_xrefs_to_field` distinguishability

**Problem.** The vanilla `get_xrefs_to_field` silently returns `[]` in
three different situations:

1. The struct doesn't exist.
2. The struct exists but the field doesn't.
3. The struct + field exist and there really are no xrefs.

Callers cannot tell these apart, so a typo in `field_name` reads as
"nothing references this field" and the analyst keeps digging for xrefs
that could never have existed. The two silent returns also `print(...)`
to backend stderr, which the shim swallows.

**Patch.** Both silent early-returns become `raise IDAError(...)` with
a clear message. `[]` now unambiguously means "no xrefs" — callers can
branch on it. Located at `mcp-plugin.py:1043-1051`.

```diff
     if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
-        print(f"Structure '{struct_name}' not found.")
-        return []
+        raise IDAError(f"Structure '{struct_name}' not found.")
     ...
     if idx == -1:
-        print(f"Field '{field_name}' not found in structure '{struct_name}'.")
-        return []
+        raise IDAError(
+            f"Field '{field_name}' not found in structure '{struct_name}'.")
```

## Re-apply after `pip install ida-pro-mcp --upgrade`

The venv installer overwrites `mcp-plugin.py`. After an upgrade:

1. Read this file.
2. Apply each patch in order to the fresh copy.
3. Run `pytest orchestrator/tests/test_ida_bridge.py` to confirm the
   bridge still passes.

If a future upstream release fixes the issue upstream, delete the
matching section here.
