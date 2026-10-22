#pragma once

// Internal helpers shared across the host_* TUs. Not part of the public
// host_info.hpp API — kept in a private header so the split TUs can reach
// the same WideToUtf8/RegRead*/IsoFromUnixSeconds/NtQSI definitions without
// duplicating them. Defined in host_info.cpp (the aggregator TU).

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <string>

namespace suspex::host::detail {

// Small RAII holder for a HANDLE that CloseHandle should reclaim.
struct HandleGuard {
    HANDLE h = INVALID_HANDLE_VALUE;
    HandleGuard() = default;
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard()
    {
        if (h != nullptr && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

std::string WideToUtf8(const wchar_t* w, int len_chars = -1);

bool RegReadString(HKEY hive, const wchar_t* subkey, const wchar_t* value,
                   std::string& out);

bool RegReadDword(HKEY hive, const wchar_t* subkey, const wchar_t* value,
                  uint32_t& out);

std::string IsoNow();
std::string IsoFromUnixSeconds(uint64_t secs);

using NtQuerySystemInformationFn = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
NtQuerySystemInformationFn NtQSIFn();

} // namespace suspex::host::detail
