// Cross-process heap enumeration (see heap_walker.hpp).
//
// Primary path: ntdll!RtlQueryProcessDebugInformation with PDI_HEAPS
// (+ PDI_HEAP_BLOCKS when the caller wants block detail). This is the
// mechanism `!heap` and Process Explorer use — undocumented, but stable
// since XP. It works cross-process by injecting a short-lived thread into
// the target to walk its RTL_HEAP structures at their native pointers.
//
// Fallback: read the target's PEB and enumerate ProcessHeaps directly
// (heap-level info only, no block chain). This lets us return SOMETHING
// for pids where the debug-info API is refused (some protected/system pids).

#include "heap_walker.hpp"

#include <windows.h>
#include <winternl.h>

#include <algorithm>

namespace suspex::pe {

namespace {

constexpr uint32_t kDefaultMaxBlocks = 4096;
constexpr uint32_t kHardMaxBlocks = 65535;

// Debug-info flag bits (ntdll)
constexpr ULONG kPdiHeaps = 0x04;
constexpr ULONG kPdiHeapBlocks = 0x10;

// RTL_HEAP_ENTRY.Flags
constexpr USHORT kHeapBusy = 0x01;
constexpr USHORT kHeapSegment = 0x02;
constexpr USHORT kHeapUncommitted = 0x100;

#pragma pack(push, 8)
struct RTL_HEAP_ENTRY {
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union {
        struct {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
};

struct RTL_HEAP_TAG {
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
};

struct RTL_HEAP_INFORMATION {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    RTL_HEAP_TAG* Tags;
    RTL_HEAP_ENTRY* Entries;
};

struct RTL_PROCESS_HEAPS {
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];
};

struct RTL_DEBUG_INFORMATION {
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    PVOID Modules;      // union with ModulesEx; not used
    PVOID BackTraces;
    RTL_PROCESS_HEAPS* Heaps;
    PVOID Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PVOID Reserved[6];
};
#pragma pack(pop)

using RtlCreateQueryDebugBufferFn = RTL_DEBUG_INFORMATION* (NTAPI*)(ULONG Size, BOOLEAN EventPair);
using RtlQueryProcessDebugInformationFn = NTSTATUS(NTAPI*)(HANDLE UniqueProcessId, ULONG DebugInfoMask,
                                                           RTL_DEBUG_INFORMATION* Buffer);
using RtlDestroyQueryDebugBufferFn = NTSTATUS(NTAPI*)(RTL_DEBUG_INFORMATION* Buffer);

struct NtdllHooks {
    RtlCreateQueryDebugBufferFn Create = nullptr;
    RtlQueryProcessDebugInformationFn Query = nullptr;
    RtlDestroyQueryDebugBufferFn Destroy = nullptr;
    bool ok() const { return Create && Query && Destroy; }
};

NtdllHooks GetHooks()
{
    NtdllHooks h;
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return h;
    h.Create = (RtlCreateQueryDebugBufferFn)GetProcAddress(nt, "RtlCreateQueryDebugBuffer");
    h.Query = (RtlQueryProcessDebugInformationFn)GetProcAddress(nt, "RtlQueryProcessDebugInformation");
    h.Destroy = (RtlDestroyQueryDebugBufferFn)GetProcAddress(nt, "RtlDestroyQueryDebugBuffer");
    return h;
}

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool ReadPebProcessHeaps(uint32_t pid, UserReadFn& user_read, std::vector<HeapRow>& out,
                         std::string& err)
{
    if (!user_read) {
        err = "no user_read fallback provided";
        return false;
    }
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) {
        err = "OpenProcess failed (fallback path)";
        return false;
    }
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto nqip = (NtQueryInformationProcessFn)GetProcAddress(nt, "NtQueryInformationProcess");
    if (!nqip) {
        CloseHandle(proc);
        err = "NtQueryInformationProcess missing";
        return false;
    }
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG got = 0;
    NTSTATUS s = nqip(proc, ProcessBasicInformation, &pbi, sizeof(pbi), &got);
    CloseHandle(proc);
    if (s < 0 || !pbi.PebBaseAddress) {
        err = "NtQueryInformationProcess PBI failed";
        return false;
    }
    // x64 PEB layout: NumberOfHeaps at +0xE8 (ULONG), ProcessHeaps at +0xF0
    // (PVOID*). Stable since Vista x64.
    uint64_t peb = (uint64_t)(uintptr_t)pbi.PebBaseAddress;
    ULONG number_of_heaps = 0;
    if (!user_read(pid, peb + 0xE8, &number_of_heaps, sizeof(number_of_heaps))) {
        err = "read PEB.NumberOfHeaps";
        return false;
    }
    if (number_of_heaps == 0 || number_of_heaps > 1024) {
        err = "implausible PEB.NumberOfHeaps";
        return false;
    }
    uint64_t process_heaps_ptr = 0;
    if (!user_read(pid, peb + 0xF0, &process_heaps_ptr, sizeof(process_heaps_ptr))) {
        err = "read PEB.ProcessHeaps";
        return false;
    }
    std::vector<uint64_t> heap_ptrs(number_of_heaps);
    if (!user_read(pid, process_heaps_ptr, heap_ptrs.data(),
                   heap_ptrs.size() * sizeof(uint64_t))) {
        err = "read ProcessHeaps array";
        return false;
    }
    for (uint64_t hp : heap_ptrs) {
        if (!hp) continue;
        HeapRow row{};
        row.handle = hp;
        row.base = hp;
        // Best-effort: read HEAP.Flags (byte offset 0x70 on x64 modern
        // builds); this is undocumented so we tolerate a failed read.
        ULONG flags = 0;
        (void)user_read(pid, hp + 0x70, &flags, sizeof(flags));
        row.flags = flags;
        out.push_back(row);
    }
    return true;
}

void EmitBlocks(const RTL_HEAP_INFORMATION& hi, uint32_t max_blocks, HeapRow& row)
{
    if (!hi.Entries || hi.NumberOfEntries == 0) return;
    uint64_t running_addr = (uint64_t)(uintptr_t)hi.BaseAddress;
    uint32_t emitted = 0;
    for (ULONG i = 0; i < hi.NumberOfEntries && emitted < max_blocks; ++i) {
        const RTL_HEAP_ENTRY& e = hi.Entries[i];
        if (e.Flags & kHeapSegment) {
            running_addr = (uint64_t)(uintptr_t)e.u.s2.FirstBlock;
            continue;
        }
        if (e.Flags & kHeapUncommitted) {
            // uncommitted range: advance but don't emit
            running_addr += (uint64_t)e.Size;
            continue;
        }
        HeapBlockRow b{};
        b.address = running_addr;
        b.size = (uint64_t)e.Size;
        b.flags = e.Flags;
        row.blocks.push_back(b);
        running_addr += (uint64_t)e.Size;
        ++emitted;
    }
}

} // namespace

bool WalkHeaps(uint32_t pid, bool want_blocks, uint32_t max_blocks,
               UserReadFn user_read, std::vector<HeapRow>& out, std::string& err)
{
    err.clear();
    out.clear();
    if (max_blocks == 0) max_blocks = kDefaultMaxBlocks;
    if (max_blocks > kHardMaxBlocks) max_blocks = kHardMaxBlocks;

    NtdllHooks hooks = GetHooks();
    if (!hooks.ok()) {
        err = "ntdll debug-info API missing";
        return ReadPebProcessHeaps(pid, user_read, out, err) || err.empty();
    }

    RTL_DEBUG_INFORMATION* buf = hooks.Create(0, FALSE);
    if (!buf) {
        err = "RtlCreateQueryDebugBuffer failed";
        return ReadPebProcessHeaps(pid, user_read, out, err);
    }
    ULONG mask = kPdiHeaps | (want_blocks ? kPdiHeapBlocks : 0);
    NTSTATUS s = hooks.Query((HANDLE)(ULONG_PTR)pid, mask, buf);
    if (s < 0 || !buf->Heaps) {
        char tmp[64];
        _snprintf_s(tmp, _TRUNCATE, "RtlQueryProcessDebugInformation NTSTATUS=%08lx", (long)s);
        err = tmp;
        hooks.Destroy(buf);
        // fall back if we can — heap-level only
        std::vector<HeapRow> peb_out;
        std::string peb_err;
        if (ReadPebProcessHeaps(pid, user_read, peb_out, peb_err)) {
            out = std::move(peb_out);
            return true;
        }
        return false;
    }

    RTL_PROCESS_HEAPS* heaps = buf->Heaps;
    for (ULONG i = 0; i < heaps->NumberOfHeaps; ++i) {
        const RTL_HEAP_INFORMATION& hi = heaps->Heaps[i];
        HeapRow row{};
        row.handle = (uint64_t)(uintptr_t)hi.BaseAddress;
        row.base = (uint64_t)(uintptr_t)hi.BaseAddress;
        row.flags = hi.Flags;
        row.committed = (uint64_t)hi.BytesCommitted;
        row.reserved = (uint64_t)hi.BytesAllocated;
        if (want_blocks) {
            EmitBlocks(hi, max_blocks, row);
        }
        out.push_back(std::move(row));
    }
    hooks.Destroy(buf);
    return true;
}

} // namespace suspex::pe
