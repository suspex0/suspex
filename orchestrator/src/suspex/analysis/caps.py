"""Capability inference — what an import/export surface *can* do.

Ported from knife's capabilities pass: an additive catalog match over
imported and exported API names. This is API-reference evidence, not
behavioral proof — a system DLL legitimately exports powerful APIs.
"""

from __future__ import annotations

# category → {severity, apis}. Severity 1 = informational, 2 = notable,
# 3 = security-relevant on its own.
CATALOG: dict[str, dict] = {
    "injection": {
        "severity": 3,
        "apis": {
            "createremotethread", "createremotethreadex",
            "ntcreatethreadex", "rtlcreateuserthread",
            "writeprocessmemory", "ntwritevirtualmemory",
            "zwwritevirtualmemory", "readprocessmemory",
            "ntreadvirtualmemory", "zwreadvirtualmemory",
            "virtualallocex", "ntallocatevirtualmemory",
            "zwallocatevirtualmemory", "virtualprotectex",
            "ntprotectvirtualmemory", "queueuserapc", "ntqueueapcthread",
            "setthreadcontext", "ntsetcontextthread", "resume_thread",
            "setwindowshookexa", "setwindowshookexw",
            "mapviewoffile", "ntmapviewofsection", "zwmapviewofsection",
        },
        "note": "remote memory write / thread hijack / APC primitives",
    },
    "dynamic_loading": {
        "severity": 2,
        "apis": {
            "loadlibrarya", "loadlibraryw", "loadlibraryexa",
            "loadlibraryexw", "getprocaddress", "ntloaddriver",
            "zwloaddriver", "iocreatedriver", "mmloadsystemimage",
            "zwsetsysteminformation", "dlopen", "dlsym",
        },
        "note": "runtime module/driver loading — hides the call graph",
    },
    "evasion": {
        "severity": 3,
        "apis": {
            "am:sicaninitialize",  # AMSI
            "virtualprotect", "ntprotectvirtualmemory",
            "zwprotectvirtualmemory", "rtladdfunctiontable",
            "ntsetinformationprocess", "zwsetinformationprocess",
        },
        "note": "memory protection flips / process-state tampering",
    },
    "anti_debug": {
        "severity": 2,
        "apis": {
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "zwqueryinformationprocess",
            "ntsetinformationthread", "zwsetinformationthread",
            "outputdebugstringa", "outputdebugstringw",
            "ntclose", "kddebuggerenabled", "kdpstub",
        },
        "note": "debugger detection / thread-hide primitives",
    },
    "persistence": {
        "severity": 2,
        "apis": {
            "regsetvaluea", "regsetvaluew", "regsetvalueexa",
            "regsetvalueexw", "regcreatekeya", "regcreatekeyw",
            "regcreatekeyexa", "regcreatekeyexw", "createservicea",
            "createservicew", "startservicea", "startservicew",
            "ntcreateservice", "schtasks",
        },
        "note": "registry/service autostart writes",
    },
    "credential_theft": {
        "severity": 3,
        "apis": {
            "cryptunprotectdata", "credenumeratea", "credenumeratew",
            "credreada", "credreadw", "lsarecoverytype", "samiconnect",
            "samrqueryinformationuser", "vaultenumeratevaults",
            "nplogonnotify", "wdigest",
        },
        "note": "credential store / DPAPI access",
    },
    "surveillance": {
        "severity": 2,
        "apis": {
            "getasynckeystate", "getkeystate", "setwindowshookex",
            "getforegroundwindow", "getwindowtexta", "getwindowtextw",
            "bitblt", "getdc", "capgetdriverdescriptiona",
            "microphone", "record",
        },
        "note": "keylogging / screen / window capture",
    },
    "network": {
        "severity": 1,
        "apis": {
            "wsastartup", "socket", "connect", "send", "recv",
            "internetopena", "internetopenw", "internetconnecta",
            "internetconnectw", "httpopenrequesta", "httpopenrequestw",
            "httpsendrequesta", "httpsendrequestw", "urldownloadtofilea",
            "urldownloadtofilew", "winhttpopen", "winhttpconnect",
            "winhttpsendrequest", "getaddrinfo", "dnsquery_a",
            "dnsquery_w", "inet_addr",
        },
        "note": "socket / HTTP client surface",
    },
    "process_exec": {
        "severity": 2,
        "apis": {
            "createprocessa", "createprocessw", "createprocessasusera",
            "createprocessasuserw", "winexec", "shellexecutea",
            "shellexecutew", "shellexecuteexa", "shellexecuteexw",
            "system", "wsprintfa", "ntcreateprocess", "zwcreateprocess",
            "rtlcreateprocessparameters", "popen",
        },
        "note": "spawns child processes / shells",
    },
    "privilege": {
        "severity": 2,
        "apis": {
            "adjusttokenprivileges", "ntadjustprivilegestoken",
            "zwadjustprivilegestoken", "openprocesstoken",
            "lookupprivilegevaluea", "lookupprivilegevaluew",
            "impersonateloggedonuser", "setthreadtoken",
            "duplicatetokenex", "createtoken",
        },
        "note": "token manipulation / privilege escalation primitives",
    },
    "crypto": {
        "severity": 1,
        "apis": {
            "cryptacquirecontexta", "cryptacquirecontextw",
            "cryptencrypt", "cryptdecrypt", "crypthashdata",
            "cryptderivekey", "cryptgenkey", "bcryptencrypt",
            "bcryptdecrypt", "bcrypthash", "bcryptgenrandom",
        },
        "note": "CryptoAPI / CNG usage",
    },
    "destruction": {
        "severity": 3,
        "apis": {
            "deletedc", "ntfscontrolfile", "deviceiocontrol",
            "writefile", "setfilepointer", "vssadmin", "bcdedit",
            "wmic",
        },
        "note": "filesystem/ioctl-level destructive surface",
    },
    "kernel_primitive": {
        "severity": 3,
        "apis": {
            "mmmapiospace", "mmmapiospaceex", "mmmaplockedpages",
            "mmmaplockedpagesspecifycache", "mmcnpvirtualmemory",
            "mmcopyvirtualmemory", "zwreadvirtualmemory",
            "zwwritevirtualmemory", "kestackattachprocess",
            "obregistercallbacks", "pssetcreatprocessnotifyroutine",
            "pssetcreatprocessnotifyroutineex",
            "pssetcreatethreadnotifyroutine", "pssetloadimagenotifyroutine",
            "cmregistercallback", "cmregistercallbackex",
            "iosetcompletionroutineex", "ntloaddriver", "zwloaddriver",
            "read_port_uchar", "write_port_uchar",
        },
        "note": "driver-level primitives: physmem map / arbitrary RW / callbacks",
    },
}


def infer_capabilities(import_names: set[str],
                       export_names: set[str] | None = None) -> list[dict]:
    """Match a binary's API surface against the catalog.

    ``import_names``/``export_names`` are bare lowercase names
    (``kernel32!writeprocessmemory`` callers should pre-strip). Returns
    ``[{category, severity, matched:[…], note}]`` sorted by severity desc.
    """
    names = {n.lower() for n in import_names}
    names |= {n.lower() for n in (export_names or set())}
    out = []
    for cat, meta in CATALOG.items():
        hits = sorted(names & meta["apis"])
        if hits:
            out.append({"category": cat, "severity": meta["severity"],
                        "matched": hits, "note": meta["note"]})
    out.sort(key=lambda r: (-r["severity"], r["category"]))
    return out
