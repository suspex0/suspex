#include "SuspexDriver.h"
#include <intrin.h>

// Idt.c — v12 per-CPU IDT enumeration (SUSPEX_IOCTL_IDT_LIST).
//
// KIDT is per-processor on x64 Windows: each CPU owns its own gate table,
// so "the IDT" is only ever the IDT of the CPU you asked. AllCpus=1 parks
// the request thread on every processor index in turn (the GROUP_AFFINITY
// pattern BpTrap.c established) and __sidt's it; AllCpus=0 reads only the
// CPU servicing the request. Gate descriptors are decoded driver-side —
// the whole dump is one IOCTL round-trip instead of an agent-side kernel
// read per entry.
//
// Every row records the IDTR.Base it was read from: identical handlers at
// different bases is what a copied/detoured table looks like, and the
// drift check belongs to the caller (orchestrator scores it), not the
// driver. Reading the table itself goes through a plain kernel-VA copy —
// the IDT is mapped read-only-but-readable on every CPU.

#pragma pack(push, 1)
typedef struct _SUSPX_IDT_READ_ENTRY {
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT16 IstIndex : 3;
    UINT16 Reserved0 : 5;
    UINT16 Type : 5;
    UINT16 Dpl : 2;
    UINT16 Present : 1;
    UINT16 OffsetMiddle;
    UINT32 OffsetHigh;
    UINT32 Reserved1;
} SUSPX_IDT_READ_ENTRY, *PSUSPX_IDT_READ_ENTRY;

// __sidt emits a 10-byte operand {limit:2, base:8} — must stay packed or
// Base reads at offset 8 instead of 2 (wild pointer -> AV on deref).
typedef struct _SUSPX_IDT_READ_R {
    UINT16 Limit;
    UINT64 Base;
} SUSPX_IDT_READ_R, *PSUSPX_IDT_READ_R;
#pragma pack(pop)

// KeGetCurrentProcessorIndexEx isn't exported by this WDK's ntoskrnl —
// ProcessorNumberEx + IndexFromNumber covers the same ground (BpTrap.c).
static ULONG SuspxIdtCpuIndex(VOID)
{
    PROCESSOR_NUMBER pn;
    ULONG idx = KeGetCurrentProcessorNumberEx(&pn);
    UNREFERENCED_PARAMETER(idx);
    return KeGetProcessorIndexFromNumber(&pn);
}

// Read this CPU's IDTR and emit decoded rows for up to maxRows of its
// entries (Rows may be NULL with MaxRows 0 once the caller's buffer is
// full — the vector count still gets reported for Required). Returns rows
// emitted; *VectorsOut = the table's declared vector count; *BaseOut/
// *LimitOut get the IDTR.
static UINT32 SuspxIdtReadCurrent(_In_ UINT32 Cpu,
                                  _Out_writes_(maxRows) PSUSPEX_IDT_ENTRY_ROW Rows,
                                  _In_ UINT32 MaxRows,
                                  _Out_ PUINT64 BaseOut, _Out_ PUINT32 LimitOut,
                                  _Out_ PUINT32 VectorsOut)
{
    SUSPX_IDT_READ_R idtr;
    PSUSPX_IDT_READ_ENTRY entries;
    UINT32 vectors, i, emitted = 0;

    __sidt(&idtr);
    *BaseOut = idtr.Base;
    *LimitOut = idtr.Limit;
    *VectorsOut = 0;
    if (!idtr.Base || idtr.Limit < sizeof(SUSPX_IDT_READ_ENTRY) - 1) {
        return 0;
    }
    entries = (PSUSPX_IDT_READ_ENTRY)(ULONG_PTR)idtr.Base;
    vectors = (UINT32)(idtr.Limit + 1) / sizeof(SUSPX_IDT_READ_ENTRY);
    if (vectors > SUSPEX_IDT_VECTORS) {
        vectors = SUSPEX_IDT_VECTORS;
    }
    *VectorsOut = vectors;
    __try {
        for (i = 0; i < vectors && emitted < MaxRows; i++) {
            PSUSPEX_IDT_ENTRY_ROW r = &Rows[emitted];
            r->Cpu = Cpu;
            r->Vector = i;
            r->HandlerVa = (UINT64)entries[i].OffsetLow
                         | ((UINT64)entries[i].OffsetMiddle << 16)
                         | ((UINT64)entries[i].OffsetHigh << 32);
            r->Selector = entries[i].Selector;
            r->Ist = entries[i].IstIndex;
            r->Dpl = entries[i].Dpl;
            r->Type = entries[i].Type;
            r->Present = entries[i].Present;
            r->IdtBase = idtr.Base;
            r->Reserved = 0;
            emitted++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A torn-down/hooked IDTR can point at unmapped memory; emit what
        // we read before the fault rather than dropping the whole CPU.
        SuspxLog("IDTLIST cpu=%u read fault after %u entries (base=%llx)",
                 Cpu, emitted, idtr.Base);
    }
    return emitted;
}

NTSTATUS SuspxIdtList(_In_ UINT32 AllCpus,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT64 FirstBase,
                      _Out_ PUINT32 FirstLimit)
{
    PSUSPEX_IDT_ENTRY_ROW rows = (PSUSPEX_IDT_ENTRY_ROW)Buffer;
    UINT32 maxRows = (UINT32)(CapacityBytes / sizeof(SUSPEX_IDT_ENTRY_ROW));
    UINT32 emitted = 0, required = 0, ncpu = 1;
    BOOLEAN firstDone = FALSE;

    *Count = 0;
    *Required = 0;
    *FirstBase = 0;
    *FirstLimit = 0;
    if (!Buffer || !maxRows) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (AllCpus) {
        ncpu = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (!ncpu || ncpu > SUSPEX_IDT_MAX_CPUS) {
            ncpu = SUSPEX_IDT_MAX_CPUS;
        }
    }

    for (ULONG i = 0; i < ncpu; i++) {
        UINT64 base = 0;
        UINT32 limit = 0, tableVectors = 0, room, wrote;
        if (AllCpus) {
            PROCESSOR_NUMBER pn;
            GROUP_AFFINITY ga, old;
            NTSTATUS st = KeGetProcessorNumberFromIndex(i, &pn);
            if (!NT_SUCCESS(st)) {
                continue; // hole in the index space
            }
            RtlZeroMemory(&ga, sizeof(ga));
            ga.Group = pn.Group;
            ga.Mask = (KAFFINITY)1 << pn.Number;
            KeSetSystemGroupAffinityThread(&ga, &old);
            room = emitted < maxRows ? maxRows - emitted : 0;
            wrote = SuspxIdtReadCurrent(i, room ? &rows[emitted] : NULL, room,
                                        &base, &limit, &tableVectors);
            KeRevertToUserGroupAffinityThread(&old);
        } else {
            room = emitted < maxRows ? maxRows - emitted : 0;
            wrote = SuspxIdtReadCurrent(SuspxIdtCpuIndex(),
                                        room ? &rows[emitted] : NULL, room,
                                        &base, &limit, &tableVectors);
        }
        if (!firstDone && base) {
            *FirstBase = base;
            *FirstLimit = limit;
            firstDone = TRUE;
        }
        // Required counts what each CPU's IDTR declared, not what fit —
        // a truncated caller learns the real total for its retry buffer.
        required += tableVectors;
        emitted += wrote;
    }

    *Count = emitted;
    *Required = required;
    if (!emitted) {
        return STATUS_UNSUCCESSFUL;
    }
    return (required > emitted) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
