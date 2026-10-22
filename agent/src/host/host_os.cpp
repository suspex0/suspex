// OS/build/version collection — see host_info.hpp.
//
// Extracted from host_info.cpp during the Phase 6d modular split.
// Behavior is byte-for-byte the same; only the file layout changed.

#include "host_info.hpp"
#include "host_internal.hpp"

#include <windows.h>
#include <winternl.h>

#include <cstdio>
#include <cstdint>
#include <string>

namespace suspex::host::detail {

void ProbeOsRelease(HostInfo& out)
{
    // RtlGetVersion is the reliable version source (ntdll bypasses the
    // ancient GetVersionEx shim compatibility table).
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto rtl = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                "RtlGetVersion");
    if (rtl != nullptr) {
        RTL_OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (rtl(&vi) == 0) {
            out.build_major = vi.dwBuildNumber;
        }
    }

    static constexpr const wchar_t* kCurrentVersion =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    RegReadString(HKEY_LOCAL_MACHINE, kCurrentVersion, L"ProductName", out.product_name);
    RegReadString(HKEY_LOCAL_MACHINE, kCurrentVersion, L"EditionID", out.edition_id);
    RegReadString(HKEY_LOCAL_MACHINE, kCurrentVersion, L"DisplayVersion", out.display_version);
    RegReadString(HKEY_LOCAL_MACHINE, kCurrentVersion, L"ReleaseId", out.release_id);
    uint32_t ubr = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, kCurrentVersion, L"UBR", ubr)) {
        out.build_ubr = ubr;
    }
    if (out.build_major != 0) {
        char buf[64];
        if (out.build_ubr != 0) {
            std::snprintf(buf, sizeof(buf), "%u.%u", out.build_major, out.build_ubr);
        } else {
            std::snprintf(buf, sizeof(buf), "%u", out.build_major);
        }
        out.full_build_string = buf;
    }

    // Install date: seconds since Unix epoch.
    uint32_t install = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, kCurrentVersion, L"InstallDate", install)) {
        out.install_date = IsoFromUnixSeconds(install);
    }

    // Boot time = now - GetTickCount64 (millisecond precision).
    uint64_t tick_ms = GetTickCount64();
    if (tick_ms > 0) {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER li{};
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        // FILETIME is 100ns intervals since 1601-01-01
        uint64_t now_100ns = li.QuadPart;
        uint64_t tick_100ns = tick_ms * 10000ULL;
        if (now_100ns > tick_100ns) {
            uint64_t boot_100ns = now_100ns - tick_100ns;
            // Convert to Unix seconds: subtract 1601->1970 delta in 100ns.
            constexpr uint64_t kEpochDelta100ns = 116444736000000000ULL;
            if (boot_100ns > kEpochDelta100ns) {
                uint64_t boot_secs = (boot_100ns - kEpochDelta100ns) / 10000000ULL;
                out.boot_time = IsoFromUnixSeconds(boot_secs);
            }
        }
    }

    // Timezone key.
    DYNAMIC_TIME_ZONE_INFORMATION tzi{};
    if (GetDynamicTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID) {
        out.timezone = WideToUtf8(tzi.TimeZoneKeyName);
    }

    // Arch — always what the OS is (not the process). Agent is built x64
    // but a WoW64 build would still want to see "x64" for the host.
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: out.arch = "x64"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: out.arch = "arm64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: out.arch = "x86"; break;
    default: out.arch = "unknown"; break;
    }
}

} // namespace suspex::host::detail
