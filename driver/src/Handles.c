#include "SuspexDriver.h"

// Handle-table enumeration for one process: SystemExtendedHandleInformation
// (class 0x40) walk filtered by pid, two-phase like the module walks. Optional
// per-entry object names use attach + ObReferenceObjectByHandle +
// ObQueryNameString — best-effort under SEH; File objects are skipped when
// resolving names (documented deadlock risk inside IO completion paths).

#define SUSPEX_SYS_HANDLE_INFO_EX_CLASS 0x40
#define SUSPEX_HANDLE_MAX_TOTAL 4000000

#pragma pack(push, 8)
typedef struct _SUSPEX_HANDLE_ENTRY_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectType;
    ULONG HandleAttributes;
    ULONG Reserved;
} SUSPEX_HANDLE_ENTRY_EX, *PSUSPEX_HANDLE_ENTRY_EX;
C_ASSERT(sizeof(SUSPEX_HANDLE_ENTRY_EX) == 0x28);

typedef struct _SUSPEX_HANDLE_INFO_EX {
    ULONG_PTR Count;
    ULONG_PTR Reserved;
    SUSPEX_HANDLE_ENTRY_EX Handles[1];
} SUSPEX_HANDLE_INFO_EX, *PSUSPEX_HANDLE_INFO_EX;
#pragma pack(pop)

// minimal prefix of OBJECT_TYPE: TypeName is the first field
typedef struct _SUSPEX_OBJECT_TYPE_MIN {
    UNICODE_STRING TypeName; // +0x00
} SUSPEX_OBJECT_TYPE_MIN, *PSUSPEX_OBJECT_TYPE_MIN;

static VOID SuspxCopyHandleName(_In_ PCUNICODE_STRING Src, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG i, w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Src->Buffer || !Src->Length) {
        return;
    }
    w = Src->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    for (i = 0; i < w; i++) {
        Dst[i] = Src->Buffer[i];
    }
}

static VOID SuspxFillTypeName(_In_ PVOID Object, _Out_ WCHAR* Dst, _In_ ULONG DstCch,
                              _Out_ PBOOLEAN IsFile)
{
    *IsFile = FALSE;
    __try {
        PSUSPEX_OBJECT_TYPE_MIN t = (PSUSPEX_OBJECT_TYPE_MIN)ObGetObjectType(Object);
        if (t) {
            SuspxCopyHandleName(&t->TypeName, Dst, DstCch);
            if (t->TypeName.Length == sizeof(L"File") - sizeof(WCHAR) &&
                t->TypeName.Buffer && t->TypeName.Buffer[0] == L'F' &&
                t->TypeName.Buffer[1] == L'i' && t->TypeName.Buffer[2] == L'l' &&
                t->TypeName.Buffer[3] == L'e') {
                *IsFile = TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    }
}

static VOID SuspxFillObjectName(_In_opt_ PVOID Object, _In_ BOOLEAN IsFile, _Out_ WCHAR* Dst,
                                _In_ ULONG DstCch)
{
    UCHAR buf[512];
    ULONG retLen = 0;
    POBJECT_NAME_INFORMATION name = (POBJECT_NAME_INFORMATION)buf;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Object || IsFile) {
        return; // File name queries can deadlock — deliberately skipped
    }
    __try {
        if (NT_SUCCESS(ObQueryNameString(Object, name, sizeof(buf), &retLen)) &&
            name->Name.Buffer && name->Name.Length) {
            SuspxCopyHandleName(&name->Name, Dst, DstCch);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    }
}

NTSTATUS SuspxHandleList(_In_ UINT64 Pid, _In_ BOOLEAN WantNames,
                         _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PUCHAR buf = NULL;
    SIZE_T size = 1 << 20;
    UINT32 cap, total = 0, written = 0;
    PSUSPEX_HANDLE_ENTRY out = (PSUSPEX_HANDLE_ENTRY)Buffer;
    PSUSPEX_HANDLE_INFO_EX info;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(SUSPEX_HANDLE_ENTRY));
    if (!Pid) {
        return STATUS_INVALID_PARAMETER;
    }

    for (;;) {
        SuspxFree(buf);
        buf = (PUCHAR)SuspxAlloc(size);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(SUSPEX_SYS_HANDLE_INFO_EX_CLASS, buf, (ULONG)size, NULL);
        if (NT_SUCCESS(st)) {
            break;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            if (size > (SIZE_T)SUSPEX_HANDLE_MAX_TOTAL * sizeof(SUSPEX_HANDLE_ENTRY_EX) + (1 << 20)) {
                SuspxFree(buf);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            size *= 2;
            continue;
        }
        SuspxFree(buf);
        return st;
    }

    info = (PSUSPEX_HANDLE_INFO_EX)buf;
    if (info->Count > SUSPEX_HANDLE_MAX_TOTAL) {
        SuspxFree(buf);
        return STATUS_INFO_LENGTH_MISMATCH; // absurd count: refuse
    }

    for (ULONG i = 0; i < info->Count && total < SUSPEX_HANDLE_MAX_TOTAL; i++) {
        PSUSPEX_HANDLE_ENTRY_EX e = &info->Handles[i];
        if ((UINT64)e->UniqueProcessId != Pid) {
            continue;
        }
        if (cap && written < cap && out) {
            PSUSPEX_HANDLE_ENTRY o = &out[written];
            PVOID obj = e->Object;
            o->Object = (UINT64)(ULONG_PTR)obj;
            o->HandleValue = (UINT64)e->HandleValue;
            o->GrantedAccess = e->GrantedAccess;
            o->ObjectTypeIndex = e->ObjectType;
            o->Reserved = 0;
            if (obj) {
                BOOLEAN isFile = FALSE;
                SuspxFillTypeName(obj, o->TypeName, SUSPEX_HANDLE_TYPE_CCH, &isFile);
                if (WantNames) {
                    SuspxFillObjectName(obj, isFile, o->Name, SUSPEX_HANDLE_NAME_CCH);
                }
            }
            written++;
        }
        total++;
    }
    SuspxFree(buf);

    *Count = written;
    *Required = total;
    SuspxLog("HANDLES pid=%llu want_names=%u -> n=%u/%u", Pid, WantNames, written, total);
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
