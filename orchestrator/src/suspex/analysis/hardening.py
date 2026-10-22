"""Exploit-mitigation audit — verify the load-config *data*, not just the
header flags. Ported from knife's ``sec`` pass: a PE with DYNAMIC_BASE set
but no .reloc still loads at its preferred base; GUARD_CF with an empty
guard table checks nothing.

Every check returns ``{check, state, detail, consequence}`` where state is
``on`` | ``off`` | ``partial`` | ``n/a`` and consequence says what the
missing mitigation buys an attacker.
"""

from __future__ import annotations

from .pe import DIR_LOADCFG, DIR_RELOC, PeImage

# IMAGE_GUARD_* flags (winnt.h) we consult in load-config GuardFlags.
GF_CF_INSTRUMENTED = 0x00000100
GF_CF_FUNCTION_TABLE_PRESENT = 0x00000400
GF_RF_INSTRUMENTED = 0x00020000
GF_RF_ENABLE = 0x00040000
GF_RF_STRICT = 0x00080000
GF_EH_CONTINUATION_TABLE_PRESENT = 0x00200000
GF_XFG_ENABLED = 0x00800000

# DllCharacteristics bits we cross-check.
DC_HIGH_ENTROPY_VA = 0x0020
DC_DYNAMIC_BASE = 0x0040
DC_FORCE_INTEGRITY = 0x0080
DC_NX_COMPAT = 0x0100
DC_NO_SEH = 0x0400
DC_GUARD_CF = 0x4000


def _relocs(img: PeImage) -> bool:
    return img.reloc_present and img.reloc_blocks > 0


def audit(img: PeImage) -> dict:
    """Run the mitigation audit over a parsed image."""
    dc = img.dll_characteristics
    lc = img.load_config
    has_lc = bool(img.directories[DIR_LOADCFG][0])
    checks: list[dict] = []

    def add(name: str, state: str, detail: str, consequence: str) -> None:
        checks.append({"check": name, "state": state, "detail": detail,
                       "consequence": consequence})

    # -- ASLR --------------------------------------------------------------
    if dc & DC_DYNAMIC_BASE:
        if _relocs(img):
            add("aslr", "on", "DYNAMIC_BASE + .reloc present",
                "image rebases; fixed-address exploitation defeated")
        else:
            add("aslr", "partial",
                "DYNAMIC_BASE set but no .reloc section",
                "loader cannot rebase — the flag is decorative; the image "
                "always lands at its preferred base")
    else:
        add("aslr", "off", "DYNAMIC_BASE clear",
            "loads at preferred base — gadgets have fixed VAs")
    if dc & DC_HIGH_ENTROPY_VA:
        add("high_entropy_va", "on", "HIGH_ENTROPY_VA set",
            "64-bit ASLR uses the full address space")
    elif img.pe32_plus:
        add("high_entropy_va", "off", "HIGH_ENTROPY_VA clear",
            "rebases are confined to the low entropy range")

    # -- NX -----------------------------------------------------------------
    if dc & DC_NX_COMPAT:
        add("nx", "on", "NX_COMPAT set", "non-executable stack enforced")
    else:
        add("nx", "off", "NX_COMPAT clear",
            "stack data pages may execute — shellcode-friendly")

    # -- /GS ----------------------------------------------------------------
    cookie = lc.get("security_cookie_va", 0)
    if cookie:
        add("stack_cookies", "on",
            f"__security_cookie at 0x{cookie:X}",
            "stack frames carry a canary checked on return")
    else:
        add("stack_cookies", "off",
            "no __security_cookie in the load config" if has_lc
            else "no load-config directory at all",
            "linear stack overflows reach the saved return address "
            "unchecked")

    # -- CFG ----------------------------------------------------------------
    if dc & DC_GUARD_CF:
        gf = lc.get("guard_flags", 0)
        table = lc.get("guard_cf_table_va", 0)
        count = lc.get("guard_cf_count", 0)
        if table and count:
            detail = (f"guard table at 0x{table:X}, {count} entries"
                      f"{', CF_INSTRUMENTED' if gf & GF_CF_INSTRUMENTED else ''}")
            add("cfg", "on", detail, "indirect calls check the target list")
        else:
            add("cfg", "partial",
                "GUARD_CF set but guard table empty/missing",
                "flag without a function table validates nothing")
        if gf & GF_XFG_ENABLED:
            add("xfg", "on", "XFG enabled in GuardFlags",
                "typed indirect-call checks")
    else:
        add("cfg", "off", "GUARD_CF clear",
            "indirect-call targets are unrestricted — vtable hijack path")

    # -- SafeSEH (x86 only) --------------------------------------------------
    if not img.pe32_plus:
        if dc & DC_NO_SEH:
            add("safeseh", "on", "NO_SEH set",
                "SEH dispatch disabled outright")
        elif lc.get("seh_table_va") and lc.get("seh_count"):
            add("safeseh", "on",
                f"{lc['seh_count']} registered handlers",
                "only listed handlers may run")
        else:
            add("safeseh", "off", "no SEH handler table",
                "exception-handler overwrite is a usable primitive")
    else:
        add("safeseh", "n/a", "x64 uses table-based unwind", "")

    # -- RFG / shadow stack ---------------------------------------------------
    gf = lc.get("guard_flags", 0)
    if gf & GF_RF_STRICT:
        add("rfg", "on", "RF_STRICT", "return-flow guard enforced")
    elif gf & (GF_RF_INSTRUMENTED | GF_RF_ENABLE):
        add("rfg", "partial", "RFG instrumented but not strict", "")
    if gf & GF_EH_CONTINUATION_TABLE_PRESENT:
        add("ehcont", "on", "EH continuation table present",
            "CET-style EH target validation metadata present")

    # -- Force integrity -------------------------------------------------------
    if dc & DC_FORCE_INTEGRITY:
        if img.cert_size:
            add("force_integrity", "on",
                f"FORCE_INTEGRITY + cert table ({img.cert_size} B)",
                "signature verified at load")
        else:
            add("force_integrity", "partial",
                "FORCE_INTEGRITY set but image is unsigned",
                "flag requests enforcement the signature can't back")

    # -- Writable+executable surface -------------------------------------------
    rwx = [s.name for s in img.sections if s.exec and s.writable]
    if rwx:
        add("rwx_sections", "off",
            ", ".join(rwx) or "<unnamed>",
            "writable+executable sections are ready-made shellcode homes")
    else:
        add("rwx_sections", "on", "no RWX sections", "")

    # -- Score ------------------------------------------------------------------
    on = sum(1 for c in checks if c["state"] == "on")
    off = sum(1 for c in checks if c["state"] == "off")
    part = sum(1 for c in checks if c["state"] == "partial")
    na = sum(1 for c in checks if c["state"] == "n/a")
    assessed = on + off + part
    exposure = (off * 2 + part) if assessed else 0
    verdict = ("WEAK" if exposure >= 4 else
               "FAIR" if exposure >= 2 else "STRONG")
    return {
        "checks": checks,
        "score": {"on": on, "off": off, "partial": part, "n_a": na,
                  "exposure": exposure, "verdict": verdict},
    }
