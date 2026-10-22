#pragma once

// usermode-only target ops: OpenProcess family + toolhelp. No comm/driver
// linkage by design — umagent is the independent second view used to
// cross-check the kernel path.

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace um {

// SE_DEBUG_NAME is a narrow literal in the headers; the W api needs wide
constexpr wchar_t SE_DEBUG_NAME_W[] = L"SeDebugPrivilege";

struct Region {
    uint64_t base = 0;
    uint64_t size = 0;
    uint32_t state = 0;
    uint32_t protect = 0;
    uint32_t type = 0;
    std::string module;
};

struct Module {
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
};

struct Process {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::string image;
    // v14: filled by the NtQuerySystemInformation path (empty on the
    // toolhelp fallback or when cmdline wasn't requested/available).
    uint32_t sessionId = 0;
    uint64_t createTime100ns = 0;  // FILETIME ticks since 1601
    std::string cmdline;
};

std::string WinError(const char* what, DWORD gle);

// best effort; failure is not fatal (restricted tokens simply stay restricted)
bool EnableDebugPriv();

// rights fallback ladders: full set first, then reduced probes; surface every
// attempted set + win32 code in *err so access-denied on protected targets
// becomes a reportable finding instead of an opaque failure
HANDLE OpenRead(uint32_t pid, std::string* err);
HANDLE OpenReadWrite(uint32_t pid, std::string* err);
HANDLE OpenVmOp(uint32_t pid, std::string* err);

// *got may be < len on partial success (returns true, caller decides);
// returns false only when zero bytes were read
bool MemRead(uint32_t pid, uint64_t addr, void* dst, size_t len, size_t* got, std::string* err);
bool MemWrite(uint32_t pid, uint64_t addr, const void* src, size_t len, size_t* written,
              std::string* err);
bool MemAlloc(uint32_t pid, uint64_t size, uint32_t protect, uint64_t* addr, std::string* err);
bool MemFree(uint32_t pid, uint64_t addr, std::string* err);
bool MemProtect(uint32_t pid, uint64_t addr, uint64_t size, uint32_t protect, uint32_t* oldProtect,
                std::string* err);

bool Regions(uint32_t pid, std::vector<Region>* out, std::string* err);
bool Modules(uint32_t pid, std::vector<Module>* out, std::string* err);
bool ProcessList(std::vector<Process>* out, std::string* err);

// v14: ProcessCommandLineInformation (class 60) — PEB cmdline without a
// manual walk. Empty on protected/PPL targets.
std::string ProcCmdline(uint32_t pid);

// v14: per-thread inventory rows from the same NtQSI(SystemProcessInfo)
// walk — lets the umagent serve Memory.ThreadList for parity with the
// agent view. pid=0 enumerates every process.
struct ThreadRowLite {
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t startVa = 0;
    uint32_t state = 0;
    uint32_t waitReason = 0;
    int32_t basePriority = 0;
};
bool ThreadRows(uint32_t pid, std::vector<ThreadRowLite>* out, std::string* err);

} // namespace um
