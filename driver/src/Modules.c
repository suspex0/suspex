#include "SuspexDriver.h"

// Kernel modules: walk PsLoadedModuleList from our own DriverSection
// (KLDR_DATA_TABLE_ENTRY — same layout as the user-mode LDR entry).
// ZwQuerySystemInformation(SystemModuleInformation) is NOT used: recent
// builds zero ImageBase there and the entry layout drifted (path moved to
// +0x28), which yielded garbage names and useless bases.
// User modules: attached PEB->Ldr InLoadOrderModuleList walk under SEH
// (64-bit list, or the 32-bit PEB32 list for WoW64 targets when
// SUSPEX_MOD_FLAG_WOW64 is set).

#pragma pack(push, 8)
typedef struct _SUSPEX_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // 0x00
    LIST_ENTRY InMemoryOrderLinks;         // 0x10
    LIST_ENTRY InInitializationOrderLinks; // 0x20
    PVOID DllBase;                         // 0x30
    PVOID EntryPoint;                      // 0x38
    ULONG SizeOfImage;                     // 0x40
    UNICODE_STRING FullDllName;            // 0x48
    UNICODE_STRING BaseDllName;            // 0x58
} SUSPEX_LDR_ENTRY, *PSUSPEX_LDR_ENTRY;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(SUSPEX_LDR_ENTRY, DllBase) == 0x30);
C_ASSERT(FIELD_OFFSET(SUSPEX_LDR_ENTRY, SizeOfImage) == 0x40);
C_ASSERT(FIELD_OFFSET(SUSPEX_LDR_ENTRY, FullDllName) == 0x48);
C_ASSERT(FIELD_OFFSET(SUSPEX_LDR_ENTRY, BaseDllName) == 0x58);

// ---- x86 (32-bit) layouts for the WoW64 walk (offsets are target-side) ----
#define SUSPEX_PEB32_LDR_OFF        0x0C
#define SUSPEX_LDR32_LIST_HEAD_OFF  0x0C // PEB_LDR_DATA32.InLoadOrderModuleList
#define SUSPEX_LDR32_DLLBASE_OFF    0x18
#define SUSPEX_LDR32_SIZEIMAGE_OFF  0x20
#define SUSPEX_LDR32_FULLNAME_OFF   0x24 // UNICODE_STRING32 {len,max,buf}
#define SUSPEX_LDR32_BASENAME_OFF   0x2C

typedef struct _SUSPEX_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer; // 32-bit VA inside the WoW64 process
} SUSPEX_UNICODE_STRING32;
C_ASSERT(sizeof(SUSPEX_UNICODE_STRING32) == 8);

static VOID SuspxReadUserString(_In_ PCUNICODE_STRING Str, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG i, w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Str->Buffer || !Str->Length) {
        return;
    }
    w = Str->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    for (i = 0; i < w; i++) {
        Dst[i] = Str->Buffer[i]; // guarded by the caller's __try
    }
}

static VOID SuspxCopyKernelString(_In_ PCUNICODE_STRING Str, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Str->Buffer || !Str->Length) {
        return;
    }
    w = Str->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    RtlCopyMemory(Dst, Str->Buffer, (SIZE_T)w * sizeof(WCHAR));
}

NTSTATUS SuspxKernelModules(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    PDRIVER_OBJECT drv = WdfDriverWdmGetDriverObject(WdfGetDriver());
    PSUSPEX_LDR_ENTRY self;
    PLIST_ENTRY head;
    NTSTATUS st;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_MODULE_ENTRY out = (PSUSPEX_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_MODULE_ENTRY));
    if (!drv || !drv->DriverSection) {
        return STATUS_INVALID_PARAMETER;
    }
    self = (PSUSPEX_LDR_ENTRY)drv->DriverSection;
    head = &self->InLoadOrderLinks;

    // the loader mutates this list under its lock; walking unlocked can tear,
    // so every dereference is guarded and a fault yields partial data
    st = STATUS_SUCCESS;
    __try {
        for (PLIST_ENTRY cur = head->Flink; cur && cur != head && total < SUSPEX_MAX_MODULES;
             cur = cur->Flink) {
            PSUSPEX_LDR_ENTRY e = CONTAINING_RECORD(cur, SUSPEX_LDR_ENTRY, InLoadOrderLinks);
            if (e->DllBase && e->BaseDllName.Buffer) {
                if (cap && written < cap && out) {
                    PSUSPEX_MODULE_ENTRY o = &out[written];
                    o->Base = (UINT64)(ULONG_PTR)e->DllBase;
                    o->Size = e->SizeOfImage;
                    SuspxCopyKernelString(&e->BaseDllName, o->Name, SUSPEX_MOD_NAME_CCH);
                    SuspxCopyKernelString(&e->FullDllName, o->Path, SUSPEX_MOD_PATH_CCH);
                    written++;
                }
                total++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        SuspxLog("KERNMODS partial after n=%u st=%x", total, GetExceptionCode());
    }
    *Count = written;
    *Required = total;
    if (NT_SUCCESS(st) && total > written) {
        st = STATUS_BUFFER_OVERFLOW;
    }
    return st;
}

static NTSTATUS SuspxUserModulesNative(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                                       _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                                       _Out_ PUINT32 Required, _In_ PEPROCESS proc)
{
    KAPC_STATE apc;
    PPEB peb;
    PVOID ldr;
    PLIST_ENTRY head;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_MODULE_ENTRY out = (PSUSPEX_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_MODULE_ENTRY));

    peb = PsGetProcessPeb(proc);
    if (!peb) {
        return STATUS_INVALID_PARAMETER;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        ldr = *(PVOID*)((PUCHAR)peb + 0x18); // PEB->Ldr
        if (!ldr) {
            st = STATUS_INVALID_PARAMETER;
            __leave;
        }
        head = (PLIST_ENTRY)((PUCHAR)ldr + 0x10); // Ldr->InLoadOrderModuleList
        for (PLIST_ENTRY cur = head->Flink; cur && cur != head && total < SUSPEX_MAX_MODULES;
             cur = cur->Flink) {
            PSUSPEX_LDR_ENTRY e = CONTAINING_RECORD(cur, SUSPEX_LDR_ENTRY, InLoadOrderLinks);
            if (cap && written < cap && out) {
                PSUSPEX_MODULE_ENTRY o = &out[written];
                o->Base = (UINT64)(ULONG_PTR)e->DllBase;
                o->Size = e->SizeOfImage;
                SuspxReadUserString(&e->FullDllName, o->Path, SUSPEX_MOD_PATH_CCH);
                SuspxReadUserString(&e->BaseDllName, o->Name, SUSPEX_MOD_NAME_CCH);
                written++;
            }
            total++;
            st = STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        SuspxLog("USERMODS partial pid=%llu after n=%u", Pid, total);
    }
    KeUnstackDetachProcess(&apc);

    *Count = written;
    *Required = total;
    if (st == STATUS_PARTIAL_COPY) {
        return st;
    }
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

static NTSTATUS SuspxUserModulesWow64(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                                      _Out_ PUINT32 Required, _In_ PEPROCESS proc)
{
    KAPC_STATE apc;
    PVOID peb32;
    ULONG ldr32, flink;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_MODULE_ENTRY out = (PSUSPEX_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_MODULE_ENTRY));

    peb32 = PsGetProcessWow64Process(proc);
    if (!peb32) {
        return STATUS_NOT_SUPPORTED; // not a WoW64 process
    }

    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        ldr32 = *(ULONG*)((PUCHAR)peb32 + SUSPEX_PEB32_LDR_OFF);
        if (!ldr32) {
            st = STATUS_INVALID_PARAMETER;
            __leave;
        }
        flink = *(ULONG*)((PUCHAR)(ULONG_PTR)ldr32 + SUSPEX_LDR32_LIST_HEAD_OFF);
        while (flink && flink != ldr32 + SUSPEX_LDR32_LIST_HEAD_OFF &&
               total < SUSPEX_MAX_MODULES) {
            UCHAR* entry = (UCHAR*)(ULONG_PTR)flink;
            ULONG dllBase = *(ULONG*)(entry + SUSPEX_LDR32_DLLBASE_OFF);
            if (dllBase && cap && written < cap && out) {
                PSUSPEX_MODULE_ENTRY o = &out[written];
                SUSPEX_UNICODE_STRING32 full, base;
                o->Base = (UINT64)dllBase;
                o->Size = *(ULONG*)(entry + SUSPEX_LDR32_SIZEIMAGE_OFF);
                full = *(SUSPEX_UNICODE_STRING32*)(entry + SUSPEX_LDR32_FULLNAME_OFF);
                base = *(SUSPEX_UNICODE_STRING32*)(entry + SUSPEX_LDR32_BASENAME_OFF);
                if (base.Buffer && base.Length) {
                    ULONG w = base.Length / sizeof(WCHAR);
                    WCHAR* src = (WCHAR*)(ULONG_PTR)base.Buffer;
                    ULONG i, n = w > SUSPEX_MOD_NAME_CCH - 1 ? SUSPEX_MOD_NAME_CCH - 1 : w;
                    for (i = 0; i < n; i++) {
                        o->Name[i] = src[i];
                    }
                }
                if (full.Buffer && full.Length) {
                    ULONG w = full.Length / sizeof(WCHAR);
                    WCHAR* src = (WCHAR*)(ULONG_PTR)full.Buffer;
                    ULONG i, n = w > SUSPEX_MOD_PATH_CCH - 1 ? SUSPEX_MOD_PATH_CCH - 1 : w;
                    for (i = 0; i < n; i++) {
                        o->Path[i] = src[i];
                    }
                }
                written++;
            }
            total++;
            flink = *(ULONG*)entry; // InLoadOrderLinks.Flink
            st = STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        SuspxLog("USERMODS(wow64) partial pid=%llu after n=%u", Pid, total);
    }
    KeUnstackDetachProcess(&apc);

    *Count = written;
    *Required = total;
    if (st == STATUS_PARTIAL_COPY) {
        return st;
    }
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

NTSTATUS SuspxUserModules(_In_ UINT64 Pid, _In_ BOOLEAN Wow64,
                          _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                          _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PEPROCESS proc;

    if (!Pid) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = Wow64 ? SuspxUserModulesWow64(Pid, Buffer, CapacityBytes, Count, Required, proc)
               : SuspxUserModulesNative(Pid, Buffer, CapacityBytes, Count, Required, proc);
    ObDereferenceObject(proc);
    return st;
}
