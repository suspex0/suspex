#include "SuspexDriver.h"

// v10 object-directory enumeration: ZwOpenDirectoryObject +
// ZwQueryDirectoryObject — the documented, version-proof path (no
// _OBJECT_DIRECTORY hash-bucket layout assumptions, which drift per build).
//
// Untrusted-namespace discipline: depth clamped to SUSPEX_OBJ_MAX_DEPTH,
// entries clamped to the caller's budget (agent caps 4096), names copied
// bounded, and only objects whose type is literally "Directory" are
// recursed into. A failing subdirectory is skipped (a hole is not
// evidence) and surfaced via the truncated flag, never as a hard error.

// OBJECT_DIRECTORY_INFORMATION is {UNICODE_STRING Name; UNICODE_STRING
// TypeName;} — declared in wdm/ntifs variants that differ across SDKs, so
// carry the layout locally (two pointers + two USHORTs, packed by the OS).
typedef struct _SUSPEX_DIR_INFO {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} SUSPEX_DIR_INFO;

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

NTKERNELAPI NTSTATUS ZwQueryDirectoryObject(_In_ HANDLE DirectoryHandle,
                                            _Out_writes_bytes_(Length) PVOID Buffer,
                                            _In_ ULONG Length,
                                            _In_ BOOLEAN ReturnSingleEntry,
                                            _In_ BOOLEAN RestartScan,
                                            _Inout_ PULONG Context,
                                            _Out_opt_ PULONG ReturnLength);

typedef struct _SUSPEX_OBJ_WALK {
    PSUSPEX_OBJ_ENTRY Out; // output array
    UINT32 Capacity;       // total entry capacity
    UINT32 Written;        // entries written so far
    UINT32 Required;       // total entries seen (incl. overflow)
    UINT32 Truncated;      // set once the budget is exhausted
} SUSPEX_OBJ_WALK;

#define SUSPEX_OBJDIR_SCRATCH 64 // SUSPEX_DIR_INFO slots per query

static VOID SuspxObjEmit(_In_ PUNICODE_STRING Name, _In_ PUNICODE_STRING TypeName,
                         _In_ BOOLEAN IsDir, _Inout_ SUSPEX_OBJ_WALK* Walk)
{
    PSUSPEX_OBJ_ENTRY e;
    ULONG wch;

    Walk->Required++;
    if (Walk->Written >= Walk->Capacity) {
        Walk->Truncated = 1;
        return;
    }
    e = &Walk->Out[Walk->Written];
    RtlZeroMemory(e, sizeof(*e));
    wch = Name->Length / sizeof(WCHAR);
    if (wch > SUSPEX_OBJ_NAME_CCH - 1) {
        wch = SUSPEX_OBJ_NAME_CCH - 1;
    }
    RtlCopyMemory(e->Name, Name->Buffer, wch * sizeof(WCHAR));
    wch = TypeName->Length / sizeof(WCHAR);
    if (wch > SUSPEX_OBJ_NAME_CCH - 1) {
        wch = SUSPEX_OBJ_NAME_CCH - 1;
    }
    RtlCopyMemory(e->TypeName, TypeName->Buffer, wch * sizeof(WCHAR));
    e->IsDirectory = IsDir ? 1 : 0;
    Walk->Written++;
}

static NTSTATUS SuspxObjWalkDir(_In_ PCWSTR Path, _In_ UINT32 Depth,
                                _Inout_ SUSPEX_OBJ_WALK* Walk)
{
    NTSTATUS st;
    UNICODE_STRING dir;
    OBJECT_ATTRIBUTES attrs;
    HANDLE h = NULL;
    SUSPEX_DIR_INFO* info = NULL;
    ULONG ctx = 0;
    BOOLEAN restart = TRUE;
    SIZE_T pathLen = 0;
    UNICODE_STRING dirType;

    st = RtlStringCchLengthW(Path, SUSPEX_OBJ_PATH_CCH, &pathLen);
    if (!NT_SUCCESS(st) || pathLen == 0 || Path[0] != L'\\') {
        return STATUS_OBJECT_NAME_INVALID;
    }

    RtlInitUnicodeString(&dir, Path);
    InitializeObjectAttributes(&attrs, &dir, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    st = ZwOpenDirectoryObject(&h, DIRECTORY_QUERY, &attrs);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    info = (SUSPEX_DIR_INFO*)SuspxAlloc(
        sizeof(SUSPEX_DIR_INFO) * SUSPEX_OBJDIR_SCRATCH);
    if (!info) {
        ZwClose(h);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlInitUnicodeString(&dirType, L"Directory");

    for (;;) {
        ULONG ret = 0;
        st = ZwQueryDirectoryObject(h, info,
                                    sizeof(SUSPEX_DIR_INFO) * SUSPEX_OBJDIR_SCRATCH,
                                    FALSE /* all that fit */, restart, &ctx, &ret);
        restart = FALSE;
        if (st == STATUS_NO_MORE_ENTRIES) {
            st = STATUS_SUCCESS;
            break;
        }
        if (st == STATUS_MORE_ENTRIES || st == STATUS_BUFFER_OVERFLOW) {
            // a full batch was returned and more remain — emit it, keep going
            st = STATUS_SUCCESS;
        } else if (!NT_SUCCESS(st)) {
            break;
        }
        for (ULONG i = 0; i < SUSPEX_OBJDIR_SCRATCH; i++) {
            if (!info[i].Name.Buffer) {
                break; // NULL-name entry terminates the batch
            }
            BOOLEAN isDir = RtlEqualUnicodeString(&info[i].TypeName, &dirType, TRUE);
            SuspxObjEmit(&info[i].Name, &info[i].TypeName, isDir, Walk);

            if (isDir && Depth > 1 && !Walk->Truncated) {
                SIZE_T nameLen = info[i].Name.Length / sizeof(WCHAR);
                if (pathLen + 1 + nameLen < SUSPEX_OBJ_PATH_CCH) {
                    WCHAR child[SUSPEX_OBJ_PATH_CCH];
                    RtlCopyMemory(child, Path, pathLen * sizeof(WCHAR));
                    child[pathLen] = L'\\';
                    RtlCopyMemory(child + pathLen + 1, info[i].Name.Buffer,
                                  nameLen * sizeof(WCHAR));
                    child[pathLen + 1 + nameLen] = L'\0';
                    // a failing child is skipped, not fatal
                    SuspxObjWalkDir(child, Depth - 1, Walk);
                } else {
                    Walk->Truncated = 1;
                }
            }
            if (Walk->Truncated) {
                break;
            }
        }
        if (Walk->Truncated) {
            break;
        }
    }

    SuspxFree(info);
    ZwClose(h);
    return st;
}

NTSTATUS SuspxObjEnum(_In_ PCWSTR Path, _In_ UINT32 Depth, _In_ UINT32 MaxEntries,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT32 Truncated)
{
    SUSPEX_OBJ_WALK walk;
    NTSTATUS st;

    *Count = 0;
    *Required = 0;
    *Truncated = 0;

    if (MaxEntries == 0 || MaxEntries > SUSPEX_OBJ_MAX_ENTRIES) {
        MaxEntries = SUSPEX_OBJ_MAX_ENTRIES;
    }
    if (Depth == 0 || Depth > SUSPEX_OBJ_MAX_DEPTH) {
        Depth = SUSPEX_OBJ_MAX_DEPTH;
    }

    walk.Out = (PSUSPEX_OBJ_ENTRY)Buffer;
    walk.Capacity = (UINT32)(CapacityBytes / sizeof(SUSPEX_OBJ_ENTRY));
    if (walk.Capacity > MaxEntries) {
        walk.Capacity = MaxEntries;
    }
    walk.Written = 0;
    walk.Required = 0;
    walk.Truncated = 0;

    st = SuspxObjWalkDir(Path, Depth, &walk);

    *Count = walk.Written;
    *Required = walk.Required;
    *Truncated = walk.Truncated;
    return st;
}
