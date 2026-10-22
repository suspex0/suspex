"""craft_test — assemble → disasm-verify → emulate.

Reference plugin for the 2026-09-11 codegen/emulate plan. Meant to be
copied and adapted; every step is optional so the LLM can chain
whichever half of the loop it needs.

The plugin talks to the codegen and emulator surfaces through the SDK
facades added alongside it (:attr:`sdk.codegen`, :attr:`sdk.emu`).
Nothing here reaches into the MCP tool layer directly, so the plugin
runs the same way from the plugin runner, from the SDK, or from a unit
test.
"""

from __future__ import annotations

from typing import Any


async def run(sdk, params: dict[str, Any]) -> dict[str, Any]:
    code = str(params["code"])
    arch = str(params.get("arch", "x64"))
    entry = int(params.get("entry", 0x1000))
    do_emu = bool(params.get("emulate", True))
    engine = str(params.get("emu_engine", "unicorn"))
    max_ins = int(params.get("emu_max_ins", 100_000))

    result: dict[str, Any] = {"ok": True, "arch": arch,
                               "entry": hex(entry)}

    # 1. Assemble
    try:
        encoded, ins_count, labels = sdk.codegen.assemble(
            code, arch, address=entry)
    except Exception as exc:
        return {"ok": False, "severity": "info",
                "summary": f"assemble failed: {exc}",
                "stage": "assemble",
                "error": str(exc)}
    result["assembly"] = {
        "bytes_hex": encoded.hex(),
        "size": len(encoded),
        "ins_count": ins_count,
        "labels": {k: hex(v) for k, v in labels.items()},
    }

    # 2. Round-trip: disassemble what we just built.
    try:
        disasm = sdk.codegen.disasm(encoded, arch, address=entry,
                                     count=max(1, ins_count) * 2 + 8)
    except Exception as exc:
        return {"ok": False, "severity": "info",
                "summary": f"disasm verify failed: {exc}",
                "stage": "disasm",
                "assembly": result["assembly"],
                "error": str(exc)}
    result["disasm"] = disasm

    # 3. Emulate (optional).
    emu_summary = ""
    if do_emu:
        try:
            session = sdk.emu.create(arch=arch, mode="shellcode",
                                      engine=engine)
        except Exception as exc:
            return {"ok": False, "severity": "info",
                    "summary": f"emulator create failed: {exc}",
                    "stage": "emulate.create",
                    "assembly": result["assembly"], "disasm": disasm,
                    "error": str(exc),
                    "hint": "engine=unicorn works when speakeasy's native "
                            "chain is broken on this Python"}
        try:
            ep = session.engine.load_shellcode(encoded, entry)
            run_out = session.engine.run(max_ins=max_ins)
            regs = session.engine.read_regs()
            result["emu"] = {
                "session_id": session.id,
                "engine": session.engine.kind,
                "entry": hex(ep),
                "halt_reason": run_out.get("halt_reason"),
                "duration_s": run_out.get("duration_s"),
                "api_calls": run_out.get("api_calls", []),
                "events": run_out.get("events", []),
                "final_regs": regs,
            }
            emu_summary = f", emu halted: {run_out.get('halt_reason', '?')}"
        finally:
            sdk.emu.close(session.id)

    first_ins = disasm[0]["mnemonic"] if disasm else "?"
    result["severity"] = "info"
    result["summary"] = (
        f"{first_ins}... ({len(disasm)} ins, {len(encoded)} bytes)"
        + emu_summary
    )
    return result
