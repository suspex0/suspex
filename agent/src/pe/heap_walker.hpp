#pragma once

// Cross-process heap enumeration via ntdll's RtlQueryProcessDebugInformation
// (the same undocumented-but-stable path !heap uses). Falls back to a
// PEB->ProcessHeaps walk (heap-level only, no blocks) via a caller-supplied
// user-mode reader when the debug-info API refuses (some system pids do).

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace suspex::pe {

using UserReadFn = std::function<bool(uint32_t pid, uint64_t addr, void* dst, size_t len)>;

struct HeapBlockRow {
    uint64_t address;
    uint64_t size;
    uint32_t flags;
};

struct HeapRow {
    uint64_t handle;      // HEAP* (target VA); equal to base for user heaps
    uint32_t flags;
    uint64_t base;
    uint64_t committed;
    uint64_t reserved;
    std::vector<HeapBlockRow> blocks;   // empty unless want_blocks
};

// pid == GetCurrentProcessId() is fine; caller must pass a valid user_read
// only when the debug-info fallback is needed. When want_blocks is false,
// no target-thread injection happens (PDI_HEAPS only). max_blocks caps the
// per-heap block count; 0 means "default 4096"; hard cap 65535.
bool WalkHeaps(uint32_t pid, bool want_blocks, uint32_t max_blocks,
               UserReadFn user_read, std::vector<HeapRow>& out, std::string& err);

} // namespace suspex::pe
