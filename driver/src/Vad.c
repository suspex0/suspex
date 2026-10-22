#include "SuspexDriver.h"

// VAD enumeration: walk EPROCESS->VadRoot. Layout verified against the LIVE
// kernel on build 26200 via kd (2026-09-05):
//   dt nt!_EPROCESS VadRoot      -> +0x558 : _RTL_AVL_TREE
//   dt nt!_RTL_AVL_TREE          -> +0x000 Root : Ptr64 (direct node pointer)
//   dt nt!_MMVAD_SHORT -b:
//     +0x000 VadNode (_RTL_BALANCED_NODE): Left +0x00, Right +0x08
//     +0x018 StartingVpn u32, +0x01c EndingVpn u32 (inclusive)
//     +0x020 StartingVpnHigh u8, +0x021 EndingVpnHigh u8, +0x022 CommitChargeHigh u8
//     +0x030 u.LongFlags u32: VadType bits 4..6, Protection bits 7..11
//     +0x034 CommitCharge u32
// PsGetProcessVadRoot is NOT exported on 24H2+ — read EPROCESS.VadRoot via the
// build-keyed offset (dynamic resolution first for older builds).

#define SUSPEX_VAD_LEFT_OFF        0x00
#define SUSPEX_VAD_RIGHT_OFF       0x08
#define SUSPEX_VAD_START_VPN_OFF   0x18
#define SUSPEX_VAD_END_VPN_OFF     0x1C
#define SUSPEX_VAD_START_HIGH_OFF  0x20
#define SUSPEX_VAD_END_HIGH_OFF    0x21
#define SUSPEX_VAD_COMMIT_HIGH_OFF 0x22
#define SUSPEX_VAD_FLAGS_OFF       0x30
#define SUSPEX_VAD_COMMIT_OFF      0x34

#define SUSPEX_VAD_FLAG_TYPE_SHIFT 4
#define SUSPEX_VAD_FLAG_TYPE_MASK  0x7
#define SUSPEX_VAD_FLAG_PROT_SHIFT 7
#define SUSPEX_VAD_FLAG_PROT_MASK  0x1F

#define SUSPEX_VAD_MAX_ENTRIES 8192
#define SUSPEX_VAD_MAX_DEPTH 128

// per-build EPROCESS.VadRoot offset (RTL_AVL_TREE: Root pointer at +0x00)
typedef struct _SUSPEX_VAD_LAYOUT {
    UINT32 EprocVadRootOff;
} SUSPEX_VAD_LAYOUT;

static const SUSPEX_VAD_LAYOUT SuspxVadLayout_26100 = { 0x558 }; // 26100/26200 (verified live)
static const SUSPEX_VAD_LAYOUT SuspxVadLayout_Legacy = { 0x7C8 }; // 22000-22621 (verify with kd)

// MmProtectToValue-style mapping: MI protection index -> Win32 PAGE_*
// (index 0-7 base, 0x10-0x17 guard, 0x18-0x1F nocache; 0x08-0x0F reserved)
static const ULONG SuspxVadProtectToWin32[32] = {
    PAGE_NOACCESS,                 PAGE_READONLY,             PAGE_EXECUTE,            PAGE_READWRITE,
    PAGE_WRITECOPY,                PAGE_EXECUTE_READ,         PAGE_EXECUTE_READWRITE,  PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,                 PAGE_READONLY,             PAGE_EXECUTE,            PAGE_READWRITE,
    PAGE_WRITECOPY,                PAGE_EXECUTE_READ,         PAGE_EXECUTE_READWRITE,  PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS | PAGE_GUARD,    PAGE_READONLY | PAGE_GUARD,    PAGE_EXECUTE | PAGE_GUARD,       PAGE_READWRITE | PAGE_GUARD,
    PAGE_WRITECOPY | PAGE_GUARD,   PAGE_EXECUTE_READ | PAGE_GUARD, PAGE_EXECUTE_READWRITE | PAGE_GUARD, PAGE_EXECUTE_WRITECOPY | PAGE_GUARD,
    PAGE_NOACCESS | PAGE_NOCACHE,  PAGE_READONLY | PAGE_NOCACHE,  PAGE_EXECUTE | PAGE_NOCACHE,     PAGE_READWRITE | PAGE_NOCACHE,
    PAGE_WRITECOPY | PAGE_NOCACHE, PAGE_EXECUTE_READ | PAGE_NOCACHE, PAGE_EXECUTE_READWRITE | PAGE_NOCACHE, PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE,
};

static const SUSPEX_VAD_LAYOUT* SuspxVadLayoutForBuild(VOID)
{
    if (SuspxNtBuild >= 26100) {
        return &SuspxVadLayout_26100;
    }
    if (SuspxNtBuild >= 22000) {
        return &SuspxVadLayout_Legacy;
    }
    return NULL;
}

// PsGetProcessVadRoot is exported on older builds but absent from 24H2+:
// resolve it dynamically when present (returns &VadRoot, Root at +0x00),
// else read EPROCESS.VadRoot via the build-keyed offset
typedef PVOID (*SUSPEX_GET_VAD_ROOT_FN)(_In_ PEPROCESS Process);

static PVOID SuspxGetVadRoot(_In_ PEPROCESS Process, _In_ const SUSPEX_VAD_LAYOUT* Layout)
{
    static SUSPEX_GET_VAD_ROOT_FN fn = NULL;
    static BOOLEAN resolved = FALSE;
    PVOID tree;

    if (!resolved) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"PsGetProcessVadRoot");
        fn = (SUSPEX_GET_VAD_ROOT_FN)(ULONG_PTR)MmGetSystemRoutineAddress(&name);
        resolved = TRUE;
    }
    if (fn) {
        tree = fn(Process);
    } else {
        __try {
            tree = *(PVOID*)((PUCHAR)Process + Layout->EprocVadRootOff);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SuspxLog("VAD: EPROCESS VadRoot read failed st=%x", GetExceptionCode());
            return NULL;
        }
    }
    if (!tree) {
        return NULL;
    }
    // RTL_AVL_TREE: the VAD tree hangs off Root (+0x00)
    __try {
        return *(PVOID*)tree;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

NTSTATUS SuspxVadList(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    const SUSPEX_VAD_LAYOUT* layout;
    PVOID root;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_VAD_ENTRY out = (PSUSPEX_VAD_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_VAD_ENTRY));

    layout = SuspxVadLayoutForBuild();
    if (!layout) {
        SuspxLog("VAD: unsupported build %u", SuspxNtBuild);
        return STATUS_NOT_SUPPORTED;
    }
    if (!Pid) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    root = SuspxGetVadRoot(proc, layout);
    if (!root) {
        ObDereferenceObject(proc);
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess((PRKPROCESS)proc, &apc);
    st = STATUS_SUCCESS;
    __try {
        // iterative in-order walk; stack of node pointers, depth-capped
        PVOID stack[SUSPEX_VAD_MAX_DEPTH];
        LONG sp = 0;
        PVOID node = root;

        while ((node || sp > 0) && total < SUSPEX_VAD_MAX_ENTRIES) {
            if (node) {
                if (sp >= SUSPEX_VAD_MAX_DEPTH) {
                    break; // corrupt tree guard
                }
                stack[sp++] = node;
                node = *(PVOID*)((PUCHAR)node + SUSPEX_VAD_LEFT_OFF);
            } else {
                UINT64 vpnStart, vpnEnd, commit;
                UINT32 flags;

                node = stack[--sp];
                vpnStart = *(UINT32*)((PUCHAR)node + SUSPEX_VAD_START_VPN_OFF) |
                           ((UINT64)*(UCHAR*)((PUCHAR)node + SUSPEX_VAD_START_HIGH_OFF) << 32);
                vpnEnd = *(UINT32*)((PUCHAR)node + SUSPEX_VAD_END_VPN_OFF) |
                         ((UINT64)*(UCHAR*)((PUCHAR)node + SUSPEX_VAD_END_HIGH_OFF) << 32);
                flags = *(UINT32*)((PUCHAR)node + SUSPEX_VAD_FLAGS_OFF);
                commit = *(UINT32*)((PUCHAR)node + SUSPEX_VAD_COMMIT_OFF) |
                         ((UINT64)*(UCHAR*)((PUCHAR)node + SUSPEX_VAD_COMMIT_HIGH_OFF) << 32);
                if (vpnEnd >= vpnStart) {
                    if (cap && written < cap && out) {
                        PSUSPEX_VAD_ENTRY o = &out[written];
                        UINT32 prot = (flags >> SUSPEX_VAD_FLAG_PROT_SHIFT) & SUSPEX_VAD_FLAG_PROT_MASK;
                        o->StartVA = vpnStart << 12;
                        o->EndVA = (vpnEnd + 1) << 12; // EndingVpn is inclusive
                        o->Protect = SuspxVadProtectToWin32[prot & 0x1F];
                        o->VadType = (flags >> SUSPEX_VAD_FLAG_TYPE_SHIFT) & SUSPEX_VAD_FLAG_TYPE_MASK;
                        o->CommitCharge = commit;
                        o->Reserved = 0;
                        written++;
                    }
                    total++;
                }
                node = *(PVOID*)((PUCHAR)node + SUSPEX_VAD_RIGHT_OFF);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        SuspxLog("VAD partial pid=%llu after n=%u st=%x", Pid, total, GetExceptionCode());
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    *Count = written;
    *Required = total;
    if (st == STATUS_PARTIAL_COPY) {
        return st;
    }
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
