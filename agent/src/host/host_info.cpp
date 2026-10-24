// Target-machine fingerprint collector — see host_info.hpp.
//
// Design notes:
//   * Every probe is best-effort. Any failure records a human-readable
//     line in probe_errors and moves on — the goal is a partially-filled
//     view is better than a missing one, and the orchestrator surfaces the
//     gaps to the LLM via the `probe_errors` field.
//   * No writes. Everything here is observational, aligned with the
//     "target-side deception is fine, analyst-side is out" scope
//     discipline in feedback_target_scope.
//   * The driver flag word (SUSPEX_PING_OUT.Flags) is trusted over
//     usermode reads when the driver is loaded, because the driver's
//     ZwQuerySystemInformation runs in KernelMode and can't be spoofed
//     by a userland shim.

#include "host_info.hpp"

#include "suspex_abi.h"

// v1.0.1 Phase 2.1: GetAdaptersAddresses for AdapterRow collection.
// winsock2.h MUST come before windows.h so the modern socket API is
// defined before the Win32 header's conditional winsock1 pull-in; the
// IP_ADAPTER_ADDRESSES / GAA_FLAG_* symbols need iphlpapi.h which pulls
// in winsock2's structs.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <windows.h>
#include <lmcons.h>
#include <sddl.h>
#include <shlwapi.h>
#include <wtsapi32.h>
#include <winternl.h>
#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace suspex::host {

namespace {

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

std::string WideToUtf8(const wchar_t* w, int len_chars = -1)
{
    if (w == nullptr || (len_chars == 0)) {
        return {};
    }
    int chars = (len_chars < 0) ? -1 : len_chars;
    int need = WideCharToMultiByte(CP_UTF8, 0, w, chars, nullptr, 0, nullptr, nullptr);
    if (need <= 0) {
        return {};
    }
    std::string out;
    out.resize((size_t)need);
    WideCharToMultiByte(CP_UTF8, 0, w, chars, out.data(), need, nullptr, nullptr);
    // If we didn't say "the whole thing" (-1), the resulting buffer has no
    // trailing NUL because we asked for exactly len_chars. When we did
    // pass -1, WideCharToMultiByte counts the NUL and we want to drop it.
    if (chars < 0 && !out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

bool RegReadString(HKEY hive, const wchar_t* subkey, const wchar_t* value,
                   std::string& out)
{
    HKEY hk = nullptr;
    if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t buf[512];
    DWORD size = sizeof(buf);
    DWORD type = 0;
    LSTATUS st = RegQueryValueExW(hk, value, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hk);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return false;
    }
    size_t chars = size / sizeof(wchar_t);
    while (chars > 0 && buf[chars - 1] == L'\0') {
        --chars;
    }
    out = WideToUtf8(buf, (int)chars);
    return true;
}

bool RegReadDword(HKEY hive, const wchar_t* subkey, const wchar_t* value,
                  uint32_t& out)
{
    HKEY hk = nullptr;
    if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) {
        return false;
    }
    DWORD v = 0;
    DWORD size = sizeof(v);
    DWORD type = 0;
    LSTATUS st = RegQueryValueExW(hk, value, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(&v), &size);
    RegCloseKey(hk);
    if (st != ERROR_SUCCESS || type != REG_DWORD) {
        return false;
    }
    out = v;
    return true;
}

std::string IsoNow()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string IsoFromUnixSeconds(uint64_t secs)
{
    time_t t = (time_t)secs;
    struct tm gm{};
    if (gmtime_s(&gm, &t) != 0) {
        return {};
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  gm.tm_year + 1900, gm.tm_mon + 1, gm.tm_mday,
                  gm.tm_hour, gm.tm_min, gm.tm_sec);
    return buf;
}

// ---------------------------------------------------------------- identity ----

void ProbeComputerNames(HostInfo& out)
{
    wchar_t name[256];
    DWORD size = _countof(name);
    if (GetComputerNameExW(ComputerNameNetBIOS, name, &size)) {
        out.computer_name = WideToUtf8(name, (int)size);
    } else {
        out.probe_errors.push_back("computer_name: GetComputerNameExW(NetBIOS) failed gle=" +
                                   std::to_string(GetLastError()));
    }
    size = _countof(name);
    if (GetComputerNameExW(ComputerNameDnsFullyQualified, name, &size)) {
        out.dns_hostname = WideToUtf8(name, (int)size);
    } else {
        out.probe_errors.push_back("dns_hostname: GetComputerNameExW(DnsFullyQualified) failed gle=" +
                                   std::to_string(GetLastError()));
    }
    size = _countof(name);
    if (GetComputerNameExW(ComputerNameDnsDomain, name, &size) && size > 0 && name[0] != 0) {
        out.domain = WideToUtf8(name, (int)size);
    }
}

void ProbeAgentUser(HostInfo& out)
{
    // Whoever the process is running as (usually SYSTEM for the service).
    wchar_t user[UNLEN + 1];
    DWORD ulen = _countof(user);
    if (GetUserNameW(user, &ulen)) {
        out.agent_run_as = WideToUtf8(user, (int)(ulen > 0 ? ulen - 1 : 0));
    } else {
        out.probe_errors.push_back("agent_run_as: GetUserNameW failed gle=" +
                                   std::to_string(GetLastError()));
    }

    // Elevation state of the agent's own token.
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        HandleGuard guard(tok);
        TOKEN_ELEVATION elev{};
        DWORD ret = 0;
        if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &ret)) {
            out.is_elevated = elev.TokenIsElevated != 0;
        }
    }
}

void ProbeConsoleUser(HostInfo& out)
{
    DWORD sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF) {
        out.probe_errors.push_back("logged_on_user: no active console session");
        return;
    }
    LPWSTR buf = nullptr;
    DWORD len = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sid, WTSUserName, &buf, &len) &&
        buf != nullptr) {
        if (buf[0] != 0) {
            out.logged_on_user = WideToUtf8(buf, (int)(len > 0 ? len - 1 : 0));
        }
        WTSFreeMemory(buf);
    } else {
        out.probe_errors.push_back("logged_on_user: WTSQuerySessionInformation failed gle=" +
                                   std::to_string(GetLastError()));
    }
}

// ---------------------------------------------------------------------- OS ----

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

// -------------------------------------------------------------- security ----

// SystemInformationClass values not in every SDK's winternl.h yet.
constexpr SYSTEM_INFORMATION_CLASS SI_SystemKernelDebuggerInformation =
    (SYSTEM_INFORMATION_CLASS)35;
constexpr SYSTEM_INFORMATION_CLASS SI_SystemCodeIntegrityInformation =
    (SYSTEM_INFORMATION_CLASS)103;
// SystemKernelVaShadowInformation — Meltdown mitigation state.
// Returns SYSTEM_KERNEL_VA_SHADOW_INFORMATION: DWORD of packed bits:
//   bit 0: KvaShadowEnabled
//   bit 1: KvaShadowUserGlobal
//   bit 2: KvaShadowPcid
//   bit 3: KvaShadowInvpcid
//   bit 4: KvaShadowRequired
//   bit 5: KvaShadowRequiredAvailable
// Introduced in Win10 1803. Older builds return STATUS_INVALID_INFO_CLASS.
constexpr SYSTEM_INFORMATION_CLASS SI_SystemKernelVaShadowInformation =
    (SYSTEM_INFORMATION_CLASS)196;

struct KVA_SHADOW_INFO {
    ULONG Flags;
};

struct KDBG {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

struct CIInfo {
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

using NtQuerySystemInformationFn = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQuerySystemInformationFn NtQSIFn()
{
    static NtQuerySystemInformationFn fn = []() {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQuerySystemInformationFn)GetProcAddress(m, "NtQuerySystemInformation")
                 : nullptr;
    }();
    return fn;
}

void ProbeCodeIntegrity(HostInfo& out, uint32_t driver_flags, bool driver_ok)
{
    // Driver source wins when the driver is loaded.
    if (driver_ok) {
        out.testsigning.value = (driver_flags & SUSPEX_FLAG_TESTSIGNING) != 0;
        out.testsigning.source = "driver";
        out.hvci.value = (driver_flags & SUSPEX_FLAG_HVCI) != 0;
        out.hvci.source = "driver";
    }
    // Even with the driver present, run the usermode probe so we can
    // cross-check and report both sources; the higher-confidence source
    // stays selected.
    auto fn = NtQSIFn();
    if (fn == nullptr) {
        if (!driver_ok) {
            out.probe_errors.push_back("code_integrity: NtQuerySystemInformation unavailable");
        }
        return;
    }
    CIInfo ci{};
    ci.Length = sizeof(ci);
    ULONG ret = 0;
    NTSTATUS st = fn((ULONG)SI_SystemCodeIntegrityInformation, &ci, sizeof(ci), &ret);
    if (NT_SUCCESS(st)) {
        constexpr ULONG kTestSigning = 0x2;
        constexpr ULONG kHvciEnabled = 0x400;
        bool testsigning = (ci.CodeIntegrityOptions & kTestSigning) != 0;
        bool hvci = (ci.CodeIntegrityOptions & kHvciEnabled) != 0;
        if (!driver_ok) {
            out.testsigning.value = testsigning;
            out.testsigning.source = "api";
            out.hvci.value = hvci;
            out.hvci.source = "api";
        }
    } else if (!driver_ok) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "0x%08lx", (unsigned long)st);
        out.probe_errors.push_back(std::string("code_integrity: ") + buf);
    }
}

void ProbeSecureBoot(HostInfo& out)
{
    // GetFirmwareEnvironmentVariable requires SE_SYSTEM_ENVIRONMENT_NAME;
    // service account (SYSTEM) has it. Legacy BIOS returns "not supported"
    // which we treat as SecureBoot off.
    DWORD needed = 0;
    BYTE val = 0;
    SetLastError(0);
    DWORD n = GetFirmwareEnvironmentVariableW(
        L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &val, sizeof(val));
    (void)needed;
    if (n == sizeof(val)) {
        out.secureboot.value = (val != 0);
        out.secureboot.source = "api";
        return;
    }
    DWORD err = GetLastError();
    // Fallback: registry — HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled
    uint32_t reg_val = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                     L"UEFISecureBootEnabled", reg_val)) {
        out.secureboot.value = reg_val != 0;
        out.secureboot.source = "registry";
        return;
    }
    if (err == ERROR_INVALID_FUNCTION) {
        // Legacy BIOS — secure boot is not supported on this firmware.
        out.secureboot.value = false;
        out.secureboot.source = "api";
        return;
    }
    out.probe_errors.push_back("secureboot: GetFirmwareEnvironmentVariable failed gle=" +
                               std::to_string(err));
}

void ProbeKernelDebugger(HostInfo& out)
{
    auto fn = NtQSIFn();
    if (fn == nullptr) {
        return;
    }
    KDBG k{};
    ULONG ret = 0;
    NTSTATUS st = fn((ULONG)SI_SystemKernelDebuggerInformation, &k, sizeof(k), &ret);
    if (NT_SUCCESS(st)) {
        out.kernel_debugger.value = (k.KernelDebuggerEnabled && !k.KernelDebuggerNotPresent);
        out.kernel_debugger.source = "api";
    } else {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "0x%08lx", (unsigned long)st);
        out.probe_errors.push_back(std::string("kernel_debugger: ") + buf);
    }
}

void ProbeVbsAndCredGuard(HostInfo& out)
{
    // Registry-only probe. WMI (Win32_DeviceGuard) is authoritative but
    // heavy and can stall on a busy target; we keep the collector fast and
    // note "registry" confidence so the LLM knows.
    static constexpr const wchar_t* kDgHvci =
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
        L"HypervisorEnforcedCodeIntegrity";
    static constexpr const wchar_t* kDgCg =
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
        L"CredentialGuard";
    static constexpr const wchar_t* kDg =
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";

    uint32_t enabled = 0;
    uint32_t vbs_ok = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, kDg, L"EnableVirtualizationBasedSecurity", vbs_ok)) {
        out.vbs_enabled.value = vbs_ok != 0;
        out.vbs_enabled.source = "registry";
    }
    if (RegReadDword(HKEY_LOCAL_MACHINE, kDgCg, L"Enabled", enabled)) {
        out.credential_guard.value = enabled != 0;
        out.credential_guard.source = "registry";
    }
    // If the HVCI scenario key sets Enabled=1, mirror into our HVCI flag
    // only when we didn't already learn it more authoritatively.
    if (out.hvci.source == "unknown") {
        if (RegReadDword(HKEY_LOCAL_MACHINE, kDgHvci, L"Enabled", enabled)) {
            out.hvci.value = enabled != 0;
            out.hvci.source = "registry";
        }
    }
}

void ProbeDriverBlocklist(HostInfo& out)
{
    // HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable
    uint32_t v = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                     L"VulnerableDriverBlocklistEnable", v)) {
        out.driver_blocklist_on.value = v != 0;
        out.driver_blocklist_on.source = "registry";
    }
}

void ProbeLsaProtected(HostInfo& out)
{
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
    uint32_t v = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                     L"RunAsPPL", v)) {
        out.lsa_protected.value = v != 0;
        out.lsa_protected.source = "registry";
    }
}

void ProbeCpuFeatures(HostInfo& out)
{
    // CPUID leaf 7 subleaf 0: EBX carries SMEP (bit 7) and SMAP (bit 20);
    // ECX carries CET_SS (bit 7). CPU-feature-present here means "the CPU
    // supports it", not "the kernel actually turned it on" — for that the
    // driver would need to probe CR4, which we skip in v1.
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, 7, 0);
    uint32_t ebx = (uint32_t)regs[1];
    uint32_t ecx = (uint32_t)regs[2];
    out.smep = (ebx & (1u << 7)) != 0;
    out.smap = (ebx & (1u << 20)) != 0;
    out.cet_shstk = (ecx & (1u << 7)) != 0;
}

void ProbeKvaShadow(HostInfo& out)
{
    // Meltdown mitigation. Not on pre-1803 boxes; older builds return
    // STATUS_INVALID_INFO_CLASS which we surface as "not present".
    auto fn = NtQSIFn();
    if (fn == nullptr) {
        out.probe_errors.push_back("kva_shadow: NtQuerySystemInformation unavailable");
        return;
    }
    KVA_SHADOW_INFO info{};
    ULONG ret = 0;
    NTSTATUS st = fn((ULONG)SI_SystemKernelVaShadowInformation,
                     &info, sizeof(info), &ret);
    if (NT_SUCCESS(st)) {
        out.kva_shadow.value = (info.Flags & 0x1u) != 0;      // KvaShadowEnabled
        out.kva_shadow.source = "api";
        return;
    }
    // 0xC0000003 == STATUS_INVALID_INFO_CLASS (pre-1803, KVA shadow class
    // didn't exist). Treat as "not present, not tampered".
    if ((ULONG)st == 0xC0000003ul) {
        out.kva_shadow.value = false;
        out.kva_shadow.source = "api";  // authoritative "N/A on this build"
        return;
    }
    char buf[80];
    std::snprintf(buf, sizeof(buf), "kva_shadow: NtQSI(196) failed 0x%08lx",
                  (unsigned long)st);
    out.probe_errors.push_back(buf);
}

void ProbePatchGuard(HostInfo& out)
{
    // We can only say "expected" or "disabled by kd". A live PG probe
    // isn't safe from userland — this is a heuristic based on the boot
    // configuration flags.
    if (out.kernel_debugger.value) {
        out.patchguard_state = "kd_disables_pg";
    } else {
        out.patchguard_state = "expected";
    }
}

// -------------------------------------------------------------- hardware ----

std::string CpuBrand()
{
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 0x80000000);
    if ((uint32_t)regs[0] < 0x80000004u) {
        return {};
    }
    char buf[49];
    std::memset(buf, 0, sizeof(buf));
    for (uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
        int r[4] = {0, 0, 0, 0};
        __cpuid(r, (int)leaf);
        std::memcpy(buf + (leaf - 0x80000002u) * 16, r, 16);
    }
    // Trim trailing spaces and NULs.
    std::string s(buf);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) {
        s.pop_back();
    }
    // Trim leading spaces too.
    size_t i = 0;
    while (i < s.size() && s[i] == ' ') ++i;
    return s.substr(i);
}

std::string HypervisorVendor()
{
    // CPUID.1:ECX bit 31 == hypervisor bit. When set, leaf 0x40000000
    // reports 12 vendor bytes in EBX/ECX/EDX.
    int r[4] = {0, 0, 0, 0};
    __cpuid(r, 1);
    if (((uint32_t)r[2] & (1u << 31)) == 0) {
        return {};
    }
    __cpuid(r, 0x40000000);
    char buf[13];
    std::memset(buf, 0, sizeof(buf));
    std::memcpy(buf + 0, &r[1], 4);
    std::memcpy(buf + 4, &r[2], 4);
    std::memcpy(buf + 8, &r[3], 4);
    return std::string(buf);
}

void ProbeHardware(HostInfo& out)
{
    out.cpu_brand = CpuBrand();

    // Cores: physical vs logical. GetLogicalProcessorInformationEx is
    // authoritative for both counts.
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
    if (len > 0) {
        std::vector<BYTE> buf(len);
        if (GetLogicalProcessorInformationEx(
                RelationProcessorCore,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) {
            uint32_t cores = 0;
            uint32_t logical = 0;
            BYTE* p = buf.data();
            BYTE* end = p + len;
            while (p < end) {
                auto* info = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)p;
                if (info->Relationship == RelationProcessorCore) {
                    ++cores;
                    for (WORD g = 0; g < info->Processor.GroupCount; ++g) {
                        // Count set bits in the group's KAFFINITY mask.
                        KAFFINITY mask = info->Processor.GroupMask[g].Mask;
                        while (mask) {
                            logical += (uint32_t)(mask & 1);
                            mask >>= 1;
                        }
                    }
                }
                p += info->Size;
            }
            out.cpu_cores = cores;
            out.cpu_logical = logical;
        }
    }
    if (out.cpu_logical == 0) {
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        out.cpu_logical = si.dwNumberOfProcessors;
    }

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        out.phys_mem_bytes = ms.ullTotalPhys;
    }

    out.hypervisor_vendor = HypervisorVendor();
    out.is_vm = !out.hypervisor_vendor.empty();
}

// ---------------------------------------------------------------- uptime ----

void ProbeUptimes(HostInfo& out, uint64_t agent_uptime_ms)
{
    // PC uptime: GetTickCount64 in ms, monotonic since last boot (does not
    // include time spent in S4/hibernation resume between the wake and the
    // clock update — Windows accounts for that in the tick).
    out.pc_uptime_ms = GetTickCount64();
    out.agent_uptime_ms = agent_uptime_ms;

    // Service uptime: query SCM for the "SuspexAgent" service state and
    // ask for its process id, then GetProcessTimes on that pid. If we're
    // not running as a service (interactive smoke test) or SCM refuses,
    // leave service_uptime_ms at 0 — the caller can compare against the
    // process uptime to notice.
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return;
    }
    SC_HANDLE svc = OpenServiceW(scm, L"SuspexAgent", SERVICE_QUERY_STATUS);
    if (svc == nullptr) {
        CloseServiceHandle(scm);
        return;
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                             sizeof(ssp), &needed) &&
        ssp.dwCurrentState == SERVICE_RUNNING && ssp.dwProcessId != 0) {
        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                  ssp.dwProcessId);
        if (proc != nullptr) {
            FILETIME creation{}, exit_ft{}, kernel_ft{}, user_ft{};
            if (GetProcessTimes(proc, &creation, &exit_ft, &kernel_ft, &user_ft)) {
                FILETIME now{};
                GetSystemTimeAsFileTime(&now);
                ULARGE_INTEGER c{}, n{};
                c.LowPart = creation.dwLowDateTime;
                c.HighPart = creation.dwHighDateTime;
                n.LowPart = now.dwLowDateTime;
                n.HighPart = now.dwHighDateTime;
                if (n.QuadPart > c.QuadPart) {
                    out.service_uptime_ms = (n.QuadPart - c.QuadPart) / 10000ULL;
                }
            }
            CloseHandle(proc);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

// ------------------------------------------------------- security products ----

void ProbeSecurityProducts(HostInfo& out)
{
    // WSC (Windows Security Center) enumeration would go here (IWSCProductList).
    // Deferred to a follow-up slice: the wscapi CLSIDs shift between SDK
    // versions and a stable cross-Win10/11 pin needs its own review pass.
    // The field intentionally stays empty rather than shipping a half-
    // working scraper — the probe_error tells the operator we tried.
    out.probe_errors.push_back(
        "security_products: WSC enumeration is a follow-up slice");
}

} // namespace

// v1.0.1 Phase 2.1: enumerate IPv4 unicast addresses via GetAdaptersAddresses.
// One row per address; adapter down + loopback are skipped. mac is
// formatted colon-separated lowercase hex. Lives outside the anonymous
// namespace so the Status gRPC handler can share it (header-exposed).
void ProbeAdapters(HostInfo& out)
{
    ULONG size = 15 * 1024;
    std::vector<unsigned char> buf(size);
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS |
                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    DWORD rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                    (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    }
    if (rc != NO_ERROR) {
        out.probe_errors.push_back("ipv4: GetAdaptersAddresses failed gle=" +
                                   std::to_string(rc));
        return;
    }
    for (auto* ad = (IP_ADAPTER_ADDRESSES*)buf.data(); ad != nullptr;
         ad = ad->Next) {
        if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        bool up = ad->OperStatus == IfOperStatusUp;
        std::string friendly = WideToUtf8(ad->FriendlyName);
        // Format MAC.
        char mac_buf[32] = {};
        if (ad->PhysicalAddressLength == 6) {
            std::snprintf(mac_buf, sizeof(mac_buf),
                          "%02x:%02x:%02x:%02x:%02x:%02x",
                          ad->PhysicalAddress[0], ad->PhysicalAddress[1],
                          ad->PhysicalAddress[2], ad->PhysicalAddress[3],
                          ad->PhysicalAddress[4], ad->PhysicalAddress[5]);
        }
        // First default gateway on this adapter (IPv4 only).
        std::string gw;
        for (auto* g = ad->FirstGatewayAddress; g != nullptr; g = g->Next) {
            if (g->Address.lpSockaddr != nullptr &&
                g->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET,
                          &((sockaddr_in*)g->Address.lpSockaddr)->sin_addr,
                          ip, sizeof(ip));
                gw = ip;
                break;
            }
        }
        for (auto* u = ad->FirstUnicastAddress; u != nullptr; u = u->Next) {
            if (u->Address.lpSockaddr == nullptr ||
                u->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET,
                      &((sockaddr_in*)u->Address.lpSockaddr)->sin_addr,
                      ip, sizeof(ip));
            HostInfo::AdapterRow row;
            row.adapter = friendly;
            row.address = ip;
            row.prefix_len = u->OnLinkPrefixLength;
            // IP_SUFFIX_ORIGIN_DHCP / IP_SUFFIX_ORIGIN_MANUAL / ...
            switch (u->SuffixOrigin) {
            case IpSuffixOriginDhcp: row.origin = "dhcp"; break;
            case IpSuffixOriginManual: row.origin = "static"; break;
            case IpSuffixOriginLinkLayerAddress: row.origin = "linklayer"; break;
            case IpSuffixOriginRandom: row.origin = "random"; break;
            default: row.origin = "unknown"; break;
            }
            row.gateway = gw;
            row.mac = mac_buf;
            row.up = up;
            out.ipv4.push_back(std::move(row));
        }
    }
}

void Collect(bool include_security_products, bool include_hardware,
             uint32_t driver_flags, bool driver_ok,
             uint64_t agent_uptime_ms, HostInfo& out)
{
    ProbeComputerNames(out);
    ProbeAgentUser(out);
    ProbeConsoleUser(out);
    ProbeOsRelease(out);
    ProbeCodeIntegrity(out, driver_flags, driver_ok);

    if (driver_ok) {
        out.secureboot.value = (driver_flags & SUSPEX_FLAG_SECUREBOOT) != 0;
        out.secureboot.source = "driver";
        out.kernel_debugger.value = (driver_flags & SUSPEX_FLAG_KERNEL_DEBUGGER) != 0;
        out.kernel_debugger.source = "driver";
    }
    // Usermode probes fill in when the driver isn't loaded, and also when
    // the driver's flag word never learned that bit (the current driver
    // doesn't populate SECUREBOOT or KERNEL_DEBUGGER).
    if (out.secureboot.source == "unknown") {
        ProbeSecureBoot(out);
    }
    if (out.kernel_debugger.source == "unknown") {
        ProbeKernelDebugger(out);
    }

    ProbeVbsAndCredGuard(out);
    ProbeDriverBlocklist(out);
    ProbeLsaProtected(out);
    ProbeCpuFeatures(out);
    ProbeKvaShadow(out);
    ProbePatchGuard(out);
    // Uptimes always fill; PC/agent uptime never fails, and service
    // uptime is best-effort.
    ProbeUptimes(out, agent_uptime_ms);

    if (include_hardware) {
        ProbeHardware(out);
    }
    if (include_security_products) {
        ProbeSecurityProducts(out);
    }
    // v1.0.1 Phase 2.1: cheap and always-on. The adapter list is small
    // (handful of rows) and the orchestrator's self-heal / rediscover
    // paths rely on it. Failures land in probe_errors instead.
    ProbeAdapters(out);
}

} // namespace suspex::host
