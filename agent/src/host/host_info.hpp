#pragma once

// Target-machine fingerprint collector — identity, OS release, security
// posture, hardware. Pure struct output; the gRPC handler in
// grpc/services.cpp copies these fields onto the wire message. This file
// deliberately does NOT include the generated proto headers so it can be
// compiled without dragging grpcpp into every Windows header order.

#include <cstdint>
#include <string>
#include <vector>

namespace suspex::host {

struct SecurityProductRow {
    std::string name;
    std::string state;    // "on" | "off" | "expired" | "snoozed" | "unknown"
    std::string version;
    std::string kind;     // "av" | "firewall" | "antispyware"
};

// A tri-state confidence tag on each posture bit, so the orchestrator can
// keep its `{value, confidence, note}` envelope honest.
struct SecurityFlag {
    bool value = false;
    // "driver"  — verified by the loaded suspex driver (highest trust)
    // "registry" — usermode registry read (trustworthy but tamperable)
    // "api"     — usermode API call (NtQuerySystemInformation, firmware var, ...)
    // "unknown" — probe failed; value is a default and must not be trusted
    std::string source = "unknown";
};

struct HostInfo {
    // Identity
    std::string computer_name;      // NetBIOS
    std::string dns_hostname;       // fully qualified DNS
    std::string domain;
    std::string logged_on_user;     // active console session user
    std::string agent_run_as;       // whoever the agent process is running as
    bool is_elevated = false;

    // OS
    std::string product_name;       // "Windows 11 Pro"
    std::string edition_id;         // "Professional"
    std::string display_version;    // "25H2"
    std::string release_id;         // "2609"
    uint32_t build_major = 0;
    uint32_t build_ubr = 0;
    std::string full_build_string;  // "26200.9186"
    std::string install_date;       // ISO8601
    std::string boot_time;          // ISO8601
    std::string timezone;
    std::string arch;               // "x64" | "arm64" | "wow64"

    // Security posture
    SecurityFlag testsigning;
    SecurityFlag hvci;
    SecurityFlag secureboot;
    SecurityFlag kernel_debugger;
    SecurityFlag vbs_enabled;
    SecurityFlag credential_guard;
    SecurityFlag driver_blocklist_on;
    SecurityFlag lsa_protected;
    bool smep = false;
    bool smap = false;
    bool cet_shstk = false;
    std::string patchguard_state;   // "expected" | "kd_disables_pg" | "unknown"
    // v0.13: Kernel VA Shadow (Meltdown mitigation) — from
    // NtQuerySystemInformation(SystemKernelVaShadowInformation=196) bit 0.
    SecurityFlag kva_shadow;

    // Hardware
    std::string cpu_brand;
    uint32_t cpu_cores = 0;
    uint32_t cpu_logical = 0;
    uint64_t phys_mem_bytes = 0;
    std::string hypervisor_vendor;
    bool is_vm = false;

    // Uptime
    uint64_t pc_uptime_ms = 0;       // GetTickCount64 at collection time
    uint64_t agent_uptime_ms = 0;    // current process lifetime
    uint64_t service_uptime_ms = 0;  // SCM service lifetime (0 if not queryable)

    // Security products
    std::vector<SecurityProductRow> security_products;

    // Diagnostics — one entry per probe that couldn't answer, human-readable.
    std::vector<std::string> probe_errors;

    // v1.0.1 Phase 2.1: network identity. One row per IPv4 unicast address
    // learned via GetAdaptersAddresses — the orchestrator uses this both
    // for the registry observed_endpoints self-heal and for the Phase 2.4
    // rediscover MAC-filter path.
    struct AdapterRow {
        std::string adapter;
        std::string address;
        uint32_t prefix_len = 0;
        std::string origin;   // "dhcp" | "static" | "unknown"
        std::string gateway;
        std::string mac;
        bool up = false;
    };
    std::vector<AdapterRow> ipv4;
};

// Populate `out` with everything the collector can answer without the
// driver's help. Never throws; every failure lands in probe_errors instead.
// `driver_flags` and `driver_ok` come from DriverMgr::Query() — when
// `driver_ok` is true, the driver-verified bits are trusted over the
// usermode reads for testsigning / hvci / secureboot / kernel-debugger.
// `agent_uptime_ms` is the current agent-process lifetime (services.cpp
// already tracks this via AgentUptimeMs()); the collector fills PC
// uptime itself and best-effort queries SCM for the service lifetime.
void Collect(bool include_security_products, bool include_hardware,
             uint32_t driver_flags, bool driver_ok,
             uint64_t agent_uptime_ms, HostInfo& out);

// Split-TU probe API. Each Probe* function fills a subset of HostInfo
// fields — see the individual host_os.cpp / host_security.cpp /
// host_kernel.cpp translation units for behavior. All are best-effort;
// any failure lands in HostInfo::probe_errors.
namespace detail {

// host_os.cpp — OS/build/version collection
void ProbeOsRelease(HostInfo& out);

// host_security.cpp — usermode security-posture probes
void ProbeSecureBoot(HostInfo& out);
void ProbeVbsAndCredGuard(HostInfo& out);
void ProbeDriverBlocklist(HostInfo& out);
void ProbeLsaProtected(HostInfo& out);
void ProbeCpuFeatures(HostInfo& out);
void ProbeSecurityProducts(HostInfo& out);

// host_kernel.cpp — kernel-structure probes via NtQuerySystemInformation
void ProbeCodeIntegrity(HostInfo& out, uint32_t driver_flags, bool driver_ok);
void ProbeKernelDebugger(HostInfo& out);
void ProbeKvaShadow(HostInfo& out);
void ProbePatchGuard(HostInfo& out);

} // namespace detail

// v1.0.1 Phase 2.1: adapter probe exposed at namespace scope so the
// Status handler can call it without the full Collect() cost (which pulls
// SCM, registry, NtQSI, ...).
void ProbeAdapters(HostInfo& out);

} // namespace suspex::host
