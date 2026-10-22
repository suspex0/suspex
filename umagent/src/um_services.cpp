#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "suspex.grpc.pb.h"

#include "um_services.hpp"
#include "umem.hpp"
#include "pe_reader.hpp"
#include "../agent/src/exec/call_user.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <map>
#include <vector>

namespace um {

void FillStatus(google::protobuf::Message* msg, const std::string& err)
{
    // every response message has an OpStatus status field at field 1
    auto* status = msg->GetReflection()->MutableMessage(msg, msg->GetDescriptor()->field(0));
    auto* st = static_cast<suspex::OpStatus*>(status);
    st->set_ok(err.empty());
    if (!err.empty()) {
        st->set_error(err);
        st->set_errno_code(1);
    }
}

namespace {

grpc::Status CheckAuth(grpc::ServerContext* ctx, const std::string& token)
{
    if (token.empty()) {
        return grpc::Status::OK;
    }
    auto md = ctx->client_metadata();
    auto it = md.find("authorization");
    if (it == md.end() || it->second != "Bearer " + token) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "missing or invalid bearer token");
    }
    return grpc::Status::OK;
}

UINT32 PidOrSelf(UINT32 pid)
{
    return pid ? pid : GetCurrentProcessId();
}

// v14: same boot/instance identity the agent reports — the orchestrator's
// boot-detection works identically against both views.
static uint64_t UmBootEpochMs()
{
    struct TimeOfDay {
        LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias;
        ULONG TimeZoneId, Reserved;
        ULONGLONG BootTimeBias, SleepTimeBias;
    } ti{};
    using NtQSIFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSIFn ntqsi = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtQSIFn)GetProcAddress(ntdll, "NtQuerySystemInformation") : nullptr;
    }();
    if (ntqsi && ntqsi(3 /*SystemTimeOfDayInformation*/, &ti, sizeof(ti), nullptr) == 0) {
        return (uint64_t)(ti.BootTime.QuadPart / 10000ULL - 11644473600000ULL);
    }
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now_ms - GetTickCount64();
}

static uint64_t UmAgentUptimeMs()
{
    static std::atomic<uint64_t> start{0};
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t s = start.load(std::memory_order_relaxed);
    if (s == 0) {
        start.compare_exchange_strong(s, now_ms);
        s = start.load(std::memory_order_relaxed);
    }
    return now_ms - s;
}

static const std::string& UmInstanceId()
{
    static const std::string id = [] {
        char buf[64];
        auto now = (unsigned long long)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snprintf(buf, sizeof(buf), "%lu-%llu", (unsigned long)GetCurrentProcessId(), now);
        return std::string(buf);
    }();
    return id;
}

// v14: lightweight register snapshot (same shape as the agent's
// SnapThreadContext) — the umagent is the driver-free view, and "regs on a
// wedged user process" is exactly what it's for.
static void UmSnapThreadContext(uint32_t pid, uint32_t tid,
                                suspex::SysThreadInfo* row,
                                std::map<DWORD, int>* wow64_cache)
{
    if (pid == GetCurrentProcessId() || tid == GetCurrentThreadId()) return;
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return;
    int wow64 = -1;
    auto it = wow64_cache->find(pid);
    if (it != wow64_cache->end()) {
        wow64 = it->second;
    } else {
        BOOL w = FALSE;
        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (ph) {
            IsWow64Process(ph, &w);
            CloseHandle(ph);
        }
        wow64 = w ? 1 : 0;
        (*wow64_cache)[pid] = wow64;
    }
    if (SuspendThread(th) != (DWORD)-1) {
        auto* m = row->mutable_context_regs();
        if (wow64 == 1) {
            WOW64_CONTEXT c{};
            c.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER |
                             WOW64_CONTEXT_SEGMENTS;
            if (Wow64GetThreadContext(th, &c)) {
                (*m)["eip"] = c.Eip;  (*m)["esp"] = c.Esp;  (*m)["ebp"] = c.Ebp;
                (*m)["eax"] = c.Eax;  (*m)["ebx"] = c.Ebx;  (*m)["ecx"] = c.Ecx;
                (*m)["edx"] = c.Edx;  (*m)["esi"] = c.Esi;  (*m)["edi"] = c.Edi;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        } else {
            CONTEXT c{};
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
            if (GetThreadContext(th, &c)) {
                (*m)["rip"] = c.Rip;  (*m)["rsp"] = c.Rsp;  (*m)["rbp"] = c.Rbp;
                (*m)["rax"] = c.Rax;  (*m)["rbx"] = c.Rbx;  (*m)["rcx"] = c.Rcx;
                (*m)["rdx"] = c.Rdx;  (*m)["rsi"] = c.Rsi;  (*m)["rdi"] = c.Rdi;
                (*m)["r8"] = c.R8;    (*m)["r9"] = c.R9;    (*m)["r10"] = c.R10;
                (*m)["r11"] = c.R11;  (*m)["r12"] = c.R12;  (*m)["r13"] = c.R13;
                (*m)["r14"] = c.R14;  (*m)["r15"] = c.R15;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        }
        ResumeThread(th);
    }
    CloseHandle(th);
}

// case-insensitive basename-or-full-path module lookup over the um::Module
// list (mirror of the agent's FindModuleBase in grpc/services.cpp)
static std::string BasenameLower(const std::string& p)
{
    size_t slash = p.find_last_of("\\/");
    std::string b = slash == std::string::npos ? p : p.substr(slash + 1);
    for (auto& ch : b) {
        ch = (char)std::tolower((unsigned char)ch);
    }
    return b;
}

static uint64_t FindModuleBase(const std::vector<um::Module>& mods, const std::string& want)
{
    std::string want_lower = BasenameLower(want);
    for (const auto& m : mods) {
        if (_stricmp(m.name.c_str(), want.c_str()) == 0 ||
            _stricmp(m.path.c_str(), want.c_str()) == 0 ||
            BasenameLower(m.name) == want_lower ||
            BasenameLower(m.path) == want_lower) {
            return m.base;
        }
    }
    return 0;
}

static std::string FindOwningModule(const std::vector<um::Module>& mods, uint64_t addr)
{
    for (const auto& m : mods) {
        if (m.size == 0) {
            continue;
        }
        if (addr >= m.base && addr < m.base + m.size) {
            return m.name;
        }
    }
    return {};
}

// ------------------------------------------------------------- Agent svc ----

class UmAgentSvc final : public suspex::Agent::Service {
public:
    explicit UmAgentSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Status(grpc::ServerContext* ctx, const suspex::StatusRequest*,
                        suspex::StatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        resp->set_agent_version("umagent/" + cfg_.version);
        OSVERSIONINFOEXW os{};
        os.dwOSVersionInfoSize = sizeof(os);
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
        auto rtl = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        if (rtl && rtl(&os) == 0) {
            resp->set_os_version("Windows " + std::to_string(os.dwMajorVersion) + "." +
                                 std::to_string(os.dwMinorVersion));
            resp->set_os_build(os.dwBuildNumber);
        }
        resp->set_driver_state(suspex::DRIVER_ABSENT);
        resp->set_agent_uptime_ms(UmAgentUptimeMs());
        resp->set_boot_epoch_ms(UmBootEpochMs());
        resp->set_agent_instance_id(UmInstanceId());
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

// ------------------------------------------------------------ Memory svc ----

class UmMemorySvc final : public suspex::Memory::Service {
public:
    explicit UmMemorySvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Read(grpc::ServerContext* ctx, const suspex::MemoryReadRequest* req,
                      suspex::MemoryReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != suspex::USER) {
            FillStatus(resp, "umagent: only USER space is served (kernel/physical need the agent+driver view)");
            return grpc::Status::OK;
        }
        if (req->size() > cfg_.maxReadBytes) {
            FillStatus(resp, "read exceeds max_read_mb");
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize(static_cast<size_t>(req->size()));
        size_t got = 0;
        std::string err;
        if (!um::MemRead(PidOrSelf(req->pid()), req->address(), resp->mutable_data()->data(),
                         static_cast<size_t>(req->size()), &got, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize(got);
        resp->set_read_bytes(got);
        FillStatus(resp, got == req->size() ? "" : "partial read: " + std::to_string(got) + "/" +
                                                              std::to_string(req->size()));
        return grpc::Status::OK;
    }

    grpc::Status Write(grpc::ServerContext* ctx, const suspex::MemoryWriteRequest* req,
                       suspex::MemoryWriteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != suspex::USER) {
            FillStatus(resp, "umagent: only USER space is served");
            return grpc::Status::OK;
        }
        size_t written = 0;
        std::string err;
        if (!um::MemWrite(PidOrSelf(req->pid()), req->address(), req->data().data(),
                          req->data().size(), &written, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_written_bytes(written);
        // v12 write_path: a usermode WriteProcessMemory store is always the
        // linear-VA path — there is no phys-remap fallback to report.
        // (1 = SUSPEX_MEM_WRITE_PATH_DIRECT_VA; umagent doesn't pull the
        // driver ABI header.)
        resp->set_write_path(1);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Alloc(grpc::ServerContext* ctx, const suspex::MemoryAllocRequest* req,
                       suspex::MemoryAllocResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel alloc unsupported");
            return grpc::Status::OK;
        }
        UINT64 addr = 0;
        std::string err;
        if (!um::MemAlloc(PidOrSelf(req->pid()), req->size(), req->protect(), &addr, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_address(addr);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Free(grpc::ServerContext* ctx, const suspex::MemoryFreeRequest* req,
                      suspex::MemoryFreeResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel free unsupported");
            return grpc::Status::OK;
        }
        std::string err;
        if (!um::MemFree(PidOrSelf(req->pid()), req->address(), &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Protect(grpc::ServerContext* ctx, const suspex::MemoryProtectRequest* req,
                         suspex::MemoryProtectResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT32 old = 0;
        std::string err;
        if (!um::MemProtect(PidOrSelf(req->pid()), req->address(), req->size(), req->protect(), &old,
                            &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_old_protect(old);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Modules(grpc::ServerContext* ctx, const suspex::ModulesRequest* req,
                         suspex::ModulesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel module list unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (const auto& m : mods) {
            auto* mi = resp->add_modules();
            mi->set_name(m.name);
            mi->set_path(m.path);
            mi->set_base(m.base);
            mi->set_size(m.size);
            mi->set_kernel(false);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ListProcesses(grpc::ServerContext* ctx, const suspex::ListProcessesRequest* req,
                               suspex::ListProcessesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<um::Process> procs;
        std::string err;
        if (!um::ProcessList(&procs, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        // v14: honor limit/offset like the agent view (was silently ignored)
        const size_t off = req ? static_cast<size_t>(req->offset() > 0 ? req->offset() : 0) : 0;
        const size_t lim = req ? static_cast<size_t>(req->limit()  > 0 ? req->limit()  : 0) : 0;
        size_t emitted = 0;
        for (size_t i = 0; i < procs.size(); ++i) {
            if (i < off) {
                continue;
            }
            if (lim && emitted >= lim) {
                break;
            }
            const auto& p = procs[i];
            auto* pi = resp->add_processes();
            pi->set_pid(p.pid);
            pi->set_parent_pid(p.parentPid);
            pi->set_image_name(p.image);
            pi->set_session_id(p.sessionId);
            pi->set_create_time_100ns(p.createTime100ns);
            if (req && req->with_cmdline()) {
                pi->set_cmdline(um::ProcCmdline(p.pid));
            }
            ++emitted;
        }
        resp->set_source("umagent");
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v14: parity with the agent view — NtQSI thread inventory, optional
    // register snapshot via with_context. kernel=true stays unsupported.
    grpc::Status ThreadList(grpc::ServerContext* ctx,
                            const suspex::ThreadListRequest* req,
                            suspex::ThreadListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel thread list unsupported (agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::ThreadRowLite> rows;
        std::string err;
        if (!um::ThreadRows(req->pid(), &rows, &err)) {
            FillStatus(resp, "thread list failed: " + err);
            return grpc::Status::OK;
        }
        for (const auto& t : rows) {
            auto* row = resp->add_threads();
            row->set_tid(t.tid);
            row->set_pid(t.pid);
            row->set_start_va(t.startVa);
            row->set_state(t.state);
            row->set_wait_reason(t.waitReason);
            row->set_base_priority(t.basePriority);
        }
        resp->set_count(static_cast<uint32_t>(rows.size()));
        resp->set_source("umagent");
        if (req->with_context()) {
            std::map<DWORD, int> wow;
            for (int i = 0; i < resp->threads_size(); ++i) {
                auto* t = resp->mutable_threads(i);
                UmSnapThreadContext(t->pid(), t->tid(), t, &wow);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Scan(grpc::ServerContext* ctx, const suspex::PatternScanRequest* req,
                      suspex::PatternScanResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != suspex::USER) {
            FillStatus(resp, "umagent: only USER space is served");
            return grpc::Status::OK;
        }
        const std::string& pat = req->pattern();
        const std::string& mask = req->mask();
        if (pat.empty() || (!mask.empty() && mask.size() != pat.size())) {
            FillStatus(resp, "invalid pattern/mask");
            return grpc::Status::OK;
        }
        UINT32 maxResults = req->max_results() ? req->max_results() : 64;
        UINT32 pid = PidOrSelf(req->pid());

        // window set: base==0 walks all committed readable space; base!=0 with
        // size==0 runs from base to the end of the region chain; else the
        // explicit [base, base+size) window
        std::vector<Range> ranges;
        if (req->base() == 0) {
            std::vector<um::Region> regions;
            std::string err;
            if (!um::Regions(pid, &regions, &err)) {
                FillStatus(resp, err);
                return grpc::Status::OK;
            }
            for (const auto& r : regions) {
                if (Readable(r.protect)) {
                    ranges.push_back({r.base, r.size});
                }
            }
        } else if (req->size() == 0) {
            std::vector<um::Region> regions;
            std::string err;
            if (!um::Regions(pid, &regions, &err)) {
                FillStatus(resp, err);
                return grpc::Status::OK;
            }
            for (const auto& r : regions) {
                if (!Readable(r.protect)) {
                    continue;
                }
                UINT64 start = std::max(r.base, req->base());
                UINT64 end = r.base + r.size;
                if (start < end) {
                    ranges.push_back({start, end - start});
                }
            }
        } else {
            ranges.push_back({req->base(), req->size()});
        }

        for (const auto& r : ranges) {
            if (resp->addresses_size() >= maxResults) {
                break;
            }
            ScanRange(pid, r.start, r.start + r.size, pat, mask, maxResults, resp);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // User-mode IAT walk: same PE parser + response shape as the agent path,
    // backed by um::MemRead instead of the driver.
    grpc::Status ModuleImports(grpc::ServerContext* ctx, const suspex::ModuleImportsRequest* req,
                               suspex::ModuleImportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel imports unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, "module list failed: " + err);
            return grpc::Status::OK;
        }
        uint64_t base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        uint32_t pid = PidOrSelf(req->pid());
        suspex::pe::ReadFn read = [pid](uint64_t addr, void* dst, size_t len) -> bool {
            size_t got = 0;
            std::string rerr;
            return um::MemRead(pid, addr, dst, len, &got, &rerr) && got == len;
        };
        std::vector<suspex::pe::IatRow> rows;
        if (!suspex::pe::ParseImports(base, read, rows, &err)) {
            FillStatus(resp, "parse imports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        for (const auto& r : rows) {
            auto* ie = resp->add_entries();
            ie->set_dll(r.dll);
            ie->set_name(r.name);
            ie->set_ordinal(r.ordinal);
            ie->set_iat_slot(r.iat_slot);
            ie->set_resolved(r.resolved);
            std::string owning = FindOwningModule(mods, r.resolved);
            ie->set_resolved_module(owning);
            // owning empty (pointer outside every loaded module) is almost
            // always a trampoline — flag it. Otherwise compare basenames.
            bool hooked = owning.empty() ||
                          BasenameLower(owning) != BasenameLower(r.dll);
            ie->set_hooked(hooked);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ModuleExports(grpc::ServerContext* ctx, const suspex::ModuleExportsRequest* req,
                               suspex::ModuleExportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel exports unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, "module list failed: " + err);
            return grpc::Status::OK;
        }
        uint64_t base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        uint32_t pid = PidOrSelf(req->pid());
        suspex::pe::ReadFn read = [pid](uint64_t addr, void* dst, size_t len) -> bool {
            size_t got = 0;
            std::string rerr;
            return um::MemRead(pid, addr, dst, len, &got, &rerr) && got == len;
        };
        std::vector<suspex::pe::ExpRow> rows;
        if (!suspex::pe::ParseExports(base, read, rows, &err)) {
            FillStatus(resp, "parse exports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        for (const auto& r : rows) {
            auto* ee = resp->add_entries();
            ee->set_name(r.name);
            ee->set_ordinal(r.ordinal);
            ee->set_rva(r.rva);
            ee->set_address(base + r.rva);
            ee->set_forwarder(r.forwarder);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    struct Range {
        UINT64 start;
        UINT64 size;
    };

    static bool Readable(UINT32 protect)
    {
        return protect != PAGE_NOACCESS && (protect & PAGE_GUARD) == 0;
    }

    static void ScanRange(UINT32 pid, UINT64 start, UINT64 end, const std::string& pat,
                          const std::string& mask, UINT32 maxResults,
                          suspex::PatternScanResponse* resp)
    {
        std::vector<BYTE> buf(0x100000);
        UINT64 cursor = start;
        while (cursor < end && resp->addresses_size() < maxResults) {
            size_t want = static_cast<size_t>(
                std::min<UINT64>(buf.size(), end - cursor));
            size_t got = 0;
            std::string err;
            if (!um::MemRead(pid, cursor, buf.data(), want, &got, &err) || !got) {
                break;
            }
            size_t limit = got >= pat.size() ? got - pat.size() + 1 : 0;
            for (size_t i = 0; i < limit && resp->addresses_size() < maxResults; i++) {
                bool match = true;
                for (size_t j = 0; j < pat.size(); j++) {
                    if (mask.empty() || mask[j] != '?') {
                        if (buf[i + j] != static_cast<BYTE>(pat[j])) {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) {
                    resp->add_addresses(cursor + i);
                }
            }
            UINT64 keep = pat.size() > 1 ? pat.size() - 1 : 0;
            cursor += got > keep ? got - keep : got;
        }
    }

    const Config& cfg_;
};

// ------------------------------------------------------------- Debug svc ----
// Regions only: VirtualQueryEx walk of the target pid. Every other Debug RPC
// keeps the generated UNIMPLEMENTED default — debugging stays an agent/dbgeng
// concern.

class UmDebugSvc final : public suspex::Debug::Service {
public:
    explicit UmDebugSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Regions(grpc::ServerContext* ctx, const suspex::MemoryRegionsRequest* req,
                         suspex::MemoryRegionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<um::Region> regions;
        std::string err;
        if (!um::Regions(req->pid(), &regions, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (const auto& r : regions) {
            auto* rr = resp->add_regions();
            rr->set_base(r.base);
            rr->set_size(r.size);
            rr->set_state(r.state);
            rr->set_protect(r.protect);
            rr->set_type(r.type);
            rr->set_module(r.module);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

// ------------------------------------------------------------- Exec svc ----
// CallFunction only (user space): the param-block trampoline rides the same
// shared call_user.cpp the agent compiles. Kernel calls need the driver —
// answered as a clean space error, not UNIMPLEMENTED.

class UmExecSvc final : public suspex::Exec::Service {
public:
    explicit UmExecSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status CallFunction(grpc::ServerContext* ctx, const suspex::CallFunctionRequest* req,
                              suspex::CallFunctionResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() == suspex::CALL_KERNEL) {
            FillStatus(resp, "call: kernel calls require the agent view (driver)");
            return grpc::Status::OK;
        }
        if (req->target_va() == 0) {
            FillStatus(resp, "call: target_va required");
            return grpc::Status::OK;
        }
        if (req->args_size() > 16) {
            FillStatus(resp, "call: argc>16");
            return grpc::Status::OK;
        }
        if (!req->pid()) {
            FillStatus(resp, "call: pid required for CALL_USER");
            return grpc::Status::OK;
        }
        std::vector<uint64_t> args;
        args.reserve((size_t)req->args_size());
        for (uint64_t a : req->args()) {
            args.push_back(a);
        }
        suspex::CallUserResult r = suspex::CallUser(
            (uint32_t)req->pid(), req->target_va(), args, req->timeout_ms(),
            (req->flags() & 0x1) != 0);
        resp->set_return_value(r.ret);
        resp->set_last_error(r.last_error);
        resp->set_exit_code(r.exit_code);
        resp->set_timed_out(r.timed_out);
        resp->set_exception(r.exception);
        if (r.exception) {
            resp->set_exception_code(r.exit_code);
        }
        resp->set_thread_tid(r.tid);
        resp->set_stub_va(r.stub_va);
        if (r.timed_out) {
            std::string msg = "call: timed out - thread left running";
            if (r.killed) {
                msg = "call: timed out and killed (kill_on_timeout)";
            } else if (r.stub_va) {
                char b[64];
                snprintf(b, sizeof(b), " (tid=%lu, stub_va=0x%llx; free via Memory.Free)",
                         (unsigned long)r.tid, (unsigned long long)r.stub_va);
                msg += b;
            }
            FillStatus(resp, msg);
            return grpc::Status::OK;
        }
        if (!r.ok) {
            FillStatus(resp, r.error.empty() ? "call: failed" : r.error);
            return grpc::Status::OK;
        }
        FillStatus(resp, r.done == 1 ? "" : "call: thread exited before stub completion");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

} // namespace

void RegisterServices(grpc::ServerBuilder& builder, const Config& cfg)
{
    static UmAgentSvc agentSvc(cfg);
    static UmMemorySvc memorySvc(cfg);
    static UmDebugSvc debugSvc(cfg);
    static UmExecSvc execSvc(cfg);
    builder.RegisterService(&agentSvc);
    builder.RegisterService(&memorySvc);
    builder.RegisterService(&debugSvc);
    builder.RegisterService(&execSvc);
}

} // namespace um
