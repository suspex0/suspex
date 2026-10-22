#include "umem.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>

namespace um {

std::string WinError(const char* what, DWORD gle)
{
    char msg[256]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, gle,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, sizeof(msg), nullptr);
    std::string s = what;
    s += " (";
    s += std::to_string(static_cast<unsigned long>(gle));
    s += ") ";
    s += msg;
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
    return s;
}

static std::string ToUtf8(const wchar_t* w)
{
    std::string out;
    if (!w) {
        return out;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n > 1) {
        out.resize(static_cast<size_t>(n - 1));
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    }
    return out;
}

bool EnableDebugPriv()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME_W, &tp.Privileges[0].Luid)) {
        CloseHandle(tok);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD gle = GetLastError();
    CloseHandle(tok);
    return gle == ERROR_SUCCESS; // ERROR_NOT_ALL_ASSIGNED means the token lacks the privilege
}

namespace {

struct RightsSet {
    DWORD rights;
    const char* label;
};

HANDLE OpenWithLadder(uint32_t pid, const RightsSet* sets, size_t n, std::string* err)
{
    DWORD lastGle = 0;
    std::string tried;
    for (size_t i = 0; i < n; i++) {
        HANDLE h = OpenProcess(sets[i].rights, FALSE, pid);
        if (h) {
            return h;
        }
        lastGle = GetLastError();
        tried += sets[i].label;
        tried += "(gle ";
        tried += std::to_string(static_cast<unsigned long>(lastGle));
        tried += ") ";
    }
    if (err) {
        *err = "OpenProcess pid " + std::to_string(pid) + " failed: " + tried;
    }
    return nullptr;
}

} // namespace

HANDLE OpenRead(uint32_t pid, std::string* err)
{
    const RightsSet sets[] = {
        {PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, "VM_READ|QUERY"},
        {PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, "VM_READ|QUERY_LIMITED"},
        {PROCESS_VM_READ, "VM_READ"},
    };
    return OpenWithLadder(pid, sets, 3, err);
}

HANDLE OpenReadWrite(uint32_t pid, std::string* err)
{
    const RightsSet sets[] = {
        {PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
         "VM_READ|VM_WRITE|VM_OP|QUERY"},
        {PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, "VM_READ|VM_WRITE|VM_OP"},
    };
    return OpenWithLadder(pid, sets, 2, err);
}

HANDLE OpenVmOp(uint32_t pid, std::string* err)
{
    const RightsSet sets[] = {
        {PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, "VM_OP|QUERY"},
        {PROCESS_VM_OPERATION, "VM_OP"},
    };
    return OpenWithLadder(pid, sets, 2, err);
}

bool MemRead(uint32_t pid, uint64_t addr, void* dst, size_t len, size_t* got, std::string* err)
{
    *got = 0;
    if (len == 0) {
        return true;
    }
    HANDLE h = OpenRead(pid, err);
    if (!h) {
        return false;
    }
    SIZE_T n = 0;
    BOOL ok = ReadProcessMemory(h, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), dst, len,
                                &n);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    *got = static_cast<size_t>(n);
    if (n == 0) {
        if (err) {
            *err = WinError("ReadProcessMemory", gle ? gle : ERROR_PARTIAL_COPY);
        }
        return false;
    }
    return true; // partial reads reported through *got
}

bool MemWrite(uint32_t pid, uint64_t addr, const void* src, size_t len, size_t* written,
              std::string* err)
{
    *written = 0;
    if (len == 0) {
        return true;
    }
    HANDLE h = OpenReadWrite(pid, err);
    if (!h) {
        return false;
    }
    SIZE_T n = 0;
    BOOL ok = WriteProcessMemory(h, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(addr)), src, len,
                                 &n);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    *written = static_cast<size_t>(n);
    if (!ok || n != len) {
        if (err) {
            *err = WinError("WriteProcessMemory", gle ? gle : ERROR_PARTIAL_COPY);
        }
        return false;
    }
    return true;
}

bool MemAlloc(uint32_t pid, uint64_t size, uint32_t protect, uint64_t* addr, std::string* err)
{
    *addr = 0;
    if (size == 0 || size > 0x7FFFFFFFull) {
        if (err) {
            *err = "invalid allocation size";
        }
        return false;
    }
    HANDLE h = OpenVmOp(pid, err);
    if (!h) {
        return false;
    }
    LPVOID p = VirtualAllocEx(h, nullptr, static_cast<SIZE_T>(size), MEM_RESERVE | MEM_COMMIT,
                              protect ? protect : PAGE_READWRITE);
    DWORD gle = p ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!p) {
        if (err) {
            *err = WinError("VirtualAllocEx", gle);
        }
        return false;
    }
    *addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p));
    return true;
}

bool MemFree(uint32_t pid, uint64_t addr, std::string* err)
{
    HANDLE h = OpenVmOp(pid, err);
    if (!h) {
        return false;
    }
    BOOL ok =
        VirtualFreeEx(h, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(addr)), 0, MEM_RELEASE);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!ok) {
        if (err) {
            *err = WinError("VirtualFreeEx", gle);
        }
        return false;
    }
    return true;
}

bool MemProtect(uint32_t pid, uint64_t addr, uint64_t size, uint32_t protect, uint32_t* oldProtect,
                std::string* err)
{
    *oldProtect = 0;
    if (size == 0 || size > 0x7FFFFFFFull) {
        if (err) {
            *err = "invalid protect size";
        }
        return false;
    }
    HANDLE h = OpenVmOp(pid, err);
    if (!h) {
        return false;
    }
    DWORD old = 0;
    BOOL ok = VirtualProtectEx(h, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(addr)),
                               static_cast<SIZE_T>(size), protect, &old);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!ok) {
        if (err) {
            *err = WinError("VirtualProtectEx", gle);
        }
        return false;
    }
    *oldProtect = old;
    return true;
}

bool Regions(uint32_t pid, std::vector<Region>* out, std::string* err)
{
    if (pid == 0) {
        pid = GetCurrentProcessId();
    }
    HANDLE h = OpenRead(pid, err);
    if (!h) {
        return false;
    }
    std::vector<Module> mods;
    Modules(pid, &mods, nullptr); // best effort attribution only

    uint64_t addr = 0;
    const uint64_t maxAddr = 0x7FFFFFFEFFFFull;
    bool queried = false;
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), &mbi,
                            sizeof(mbi))) {
            if (!queried && err) {
                *err = WinError("VirtualQueryEx", GetLastError());
            }
            break;
        }
        queried = true;
        uint64_t rbase = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(mbi.BaseAddress));
        uint64_t rsize = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) {
            Region r;
            r.base = rbase;
            r.size = rsize;
            r.state = mbi.State;
            r.protect = mbi.Protect;
            r.type = mbi.Type;
            for (const auto& m : mods) {
                if (rbase >= m.base && rbase < m.base + m.size) {
                    r.module = m.name;
                    break;
                }
            }
            out->push_back(std::move(r));
        }
        uint64_t next = rbase + rsize;
        if (next <= addr) {
            break; // region-size overflow guard
        }
        addr = next;
    }
    CloseHandle(h);
    if (!queried) {
        return false;
    }
    return true;
}

bool Modules(uint32_t pid, std::vector<Module>* out, std::string* err)
{
    if (pid == 0) {
        pid = GetCurrentProcessId();
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        if (err) {
            *err = WinError("CreateToolhelp32Snapshot", GetLastError());
        }
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            Module m;
            m.base = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(me.modBaseAddr));
            m.size = me.modBaseSize;
            m.name = ToUtf8(me.szModule);
            m.path = ToUtf8(me.szExePath);
            out->push_back(std::move(m));
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    if (out->empty()) {
        if (err) {
            *err = "module walk returned no entries (target may be elevated/protected)";
        }
        return false;
    }
    return true;
}

namespace {

// v14: NtQuerySystemInformation(SystemProcessInformation) is driver-free,
// session-agnostic, and can't come back legitimately empty on a live box —
// the toolhelp snapshot below stays only as a fallback now.
#pragma pack(push, 8)
struct UM_SPI_PROCESS {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    USHORT ImageNameLen;
    USHORT ImageNameMax;
    ULONG  ImageNamePad;
    ULONGLONG ImageNameBuffer;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
    // UM_SPI_THREAD[NumberOfThreads] follows — the full layout matters:
    // ThreadRows() strides the thread array off sizeof(this), and a
    // truncated struct reads pool counters as thread rows.
};
struct UM_SPI_THREAD {
    ULONGLONG KernelTime;
    ULONGLONG UserTime;
    ULONGLONG CreateTime;
    ULONG WaitTime;
    ULONGLONG StartAddress;
    ULONGLONG ClientProcessId;
    ULONGLONG ClientThreadId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};
#pragma pack(pop)

bool ProcessListNtQsi(std::vector<Process>* out, std::string* err)
{
    using NtQSI_t = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSI_t qsi = []() {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQSI_t)GetProcAddress(m, "NtQuerySystemInformation") : nullptr;
    }();
    if (!qsi) {
        if (err) *err = "NtQuerySystemInformation unavailable";
        return false;
    }
    ULONG size = 1u << 20;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<BYTE> blob(size);
        LONG st = qsi(5 /*SystemProcessInformation*/, blob.data(), size, nullptr);
        if (st == (LONG)0xC0000004L) {  // STATUS_INFO_LENGTH_MISMATCH
            size *= 2;
            continue;
        }
        if (st < 0) {
            if (err) {
                char b[32];
                snprintf(b, sizeof(b), "0x%08lX", (unsigned long)(ULONG)st);
                *err = std::string("NtQuerySystemInformation nt=") + b;
            }
            return false;
        }
        BYTE* p = blob.data();
        while (p + sizeof(UM_SPI_PROCESS) <= blob.data() + size) {
            auto* pi = (UM_SPI_PROCESS*)p;
            Process r;
            r.pid = static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(pi->UniqueProcessId));
            r.parentPid = static_cast<uint32_t>(
                reinterpret_cast<ULONG_PTR>(pi->InheritedFromUniqueProcessId));
            r.sessionId = pi->SessionId;
            r.createTime100ns = pi->CreateTime;
            if (pi->ImageNameLen && pi->ImageNameBuffer) {
                std::wstring w(reinterpret_cast<const wchar_t*>(pi->ImageNameBuffer),
                               pi->ImageNameLen / sizeof(wchar_t));
                r.image = ToUtf8(w.c_str());
            }
            out->push_back(std::move(r));
            if (!pi->NextEntryOffset) {
                break;
            }
            p += pi->NextEntryOffset;
        }
        return true;
    }
    if (err) *err = "NtQuerySystemInformation buffer retry exhausted";
    return false;
}

} // namespace

bool ProcessList(std::vector<Process>* out, std::string* err)
{
    std::string nqsi_err;
    if (ProcessListNtQsi(out, &nqsi_err) && !out->empty()) {
        return true;
    }
    out->clear();  // paranoia: never mix NtQSI rows with a toolhelp tail

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (err) {
            *err = "NtQSI: " + nqsi_err + " | toolhelp: " +
                   WinError("CreateToolhelp32Snapshot", GetLastError());
        }
        return false;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            Process p;
            p.pid = pe.th32ProcessID;
            p.parentPid = pe.th32ParentProcessID;
            p.image = ToUtf8(pe.szExeFile);
            out->push_back(std::move(p));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (out->empty()) {
        if (err) {
            *err = "process snapshot returned no entries (NtQSI: " + nqsi_err + ")";
        }
        return false;
    }
    return true;
}

std::string ProcCmdline(uint32_t pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        return {};
    }
    using NtQIP_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQIP_t qip = [] {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQIP_t)GetProcAddress(m, "NtQueryInformationProcess") : nullptr;
    }();
    // UNICODE_STRING layout, hand-rolled — winternl.h collides with the
    // LONG instead of NTSTATUS — this TU only pulls windows.h.
    struct LocalUS {
        USHORT Length;
        USHORT MaximumLength;
        ULONGLONG Buffer;
    };
    std::string out;
    if (qip) {
        std::vector<BYTE> buf(sizeof(LocalUS) + 0x4000);
        auto* us = reinterpret_cast<LocalUS*>(buf.data());
        if (qip(h, 60 /*ProcessCommandLineInformation*/, buf.data(),
                static_cast<ULONG>(buf.size()), nullptr) >= 0 && us->Buffer && us->Length) {
            std::wstring w(reinterpret_cast<const wchar_t*>(
                               static_cast<uintptr_t>(us->Buffer)),
                           us->Length / sizeof(wchar_t));
            out = ToUtf8(w.c_str());
        }
    }
    CloseHandle(h);
    return out;
}

bool ThreadRows(uint32_t pid, std::vector<ThreadRowLite>* out, std::string* err)
{
    using NtQSI_t = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSI_t qsi = []() {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQSI_t)GetProcAddress(m, "NtQuerySystemInformation") : nullptr;
    }();
    if (!qsi) {
        if (err) *err = "NtQuerySystemInformation unavailable";
        return false;
    }
    ULONG size = 1u << 20;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<BYTE> blob(size);
        LONG st = qsi(5, blob.data(), size, nullptr);
        if (st == (LONG)0xC0000004L) {
            size *= 2;
            continue;
        }
        if (st < 0) {
            if (err) {
                char b[32];
                snprintf(b, sizeof(b), "0x%08lX", (unsigned long)(ULONG)st);
                *err = std::string("NtQuerySystemInformation nt=") + b;
            }
            return false;
        }
        BYTE* p = blob.data();
        while (p + sizeof(UM_SPI_PROCESS) <= blob.data() + size) {
            auto* pi = (UM_SPI_PROCESS*)p;
            bool want = (pid == 0) ||
                        (pid == static_cast<uint32_t>(
                             reinterpret_cast<ULONG_PTR>(pi->UniqueProcessId)));
            if (want) {
                BYTE* th = p + sizeof(UM_SPI_PROCESS);
                for (ULONG t = 0; t < pi->NumberOfThreads; ++t) {
                    auto* ti = reinterpret_cast<UM_SPI_THREAD*>(th);
                    ThreadRowLite r;
                    r.pid = static_cast<uint32_t>(ti->ClientProcessId);
                    r.tid = static_cast<uint32_t>(ti->ClientThreadId);
                    r.startVa = ti->StartAddress;
                    r.state = ti->ThreadState;
                    r.waitReason = ti->WaitReason;
                    r.basePriority = ti->BasePriority;
                    out->push_back(r);
                    th += sizeof(UM_SPI_THREAD);
                }
            }
            if (!pi->NextEntryOffset) {
                break;
            }
            p += pi->NextEntryOffset;
        }
        return true;
    }
    if (err) *err = "NtQuerySystemInformation buffer retry exhausted";
    return false;
}

} // namespace um
