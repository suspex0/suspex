#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "suspex.grpc.pb.h"
#include "suspex_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include "services.hpp"
#include "services_internal.hpp"
#include "../breadcrumb.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../host/host_info.hpp"
#include "../pe/pe_reader.hpp"
#include "../pe/heap_walker.hpp"
#include "../watch.hpp"

#include <tlhelp32.h>
#include <fstream>
#include <cctype>

namespace suspex {

grpc::Status CheckAuth(::grpc::ServerContext* ctx, const std::string& token)
{
    if (token.empty()) {
        return grpc::Status::OK; // dev mode without token
    }
    auto md = ctx->client_metadata();
    auto it = md.find("authorization");
    if (it == md.end() || it->second != "Bearer " + token) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "missing or invalid bearer token");
    }
    return grpc::Status::OK;
}

bool UserMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len)
{
    auto* c = (MemReaderCtx*)ctx;
    SIZE_T got = 0;
    if (c->drv && c->drv->Comm().MemRead(Space::User, pid, addr, dst, len, &got) && got == len) {
        return true;
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        return false;
    }
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, dst, len, &read);
    CloseHandle(h);
    return ok && read == len;
}

bool KernelMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len)
{
    (void)pid;
    auto* c = (MemReaderCtx*)ctx;
    SIZE_T got = 0;
    return c->drv && c->drv->Comm().MemRead(Space::Kernel, 0, addr, dst, len, &got) &&
           got == len;
}

bool ListUserModules(DriverMgr* drv, UINT32 pid, std::vector<suspex::ModuleEntry>* out)
{
    if (drv && drv->Comm().Open() && drv->Comm().UserModules(pid, *out)) {
        return true;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            suspex::ModuleEntry e;
            e.Base = (UINT64)(uintptr_t)me.modBaseAddr;
            e.Size = me.modBaseSize;
            e.Name = me.szModule;
            e.Path = me.szExePath;
            out->push_back(e);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return !out->empty();
}

std::string BasenameLower(const std::string& p)
{
    size_t slash = p.find_last_of("\\/");
    std::string b = slash == std::string::npos ? p : p.substr(slash + 1);
    for (auto& ch : b) {
        ch = (char)std::tolower((unsigned char)ch);
    }
    return b;
}

UINT64 FindModuleBase(const std::vector<suspex::ModuleEntry>& mods,
                      const std::string& want)
{
    // match either basename or full path, case-insensitively (see DumpModule
    // in services2.cpp for the reference pattern).
    std::string want_lower = BasenameLower(want);
    for (const auto& m : mods) {
        std::string name(m.Name.begin(), m.Name.end());
        std::string path(m.Path.begin(), m.Path.end());
        if (_stricmp(name.c_str(), want.c_str()) == 0 ||
            _stricmp(path.c_str(), want.c_str()) == 0 ||
            BasenameLower(name) == want_lower ||
            BasenameLower(path) == want_lower) {
            return m.Base;
        }
    }
    return 0;
}

std::string FindOwningModule(const std::vector<suspex::ModuleEntry>& mods, UINT64 addr)
{
    for (const auto& m : mods) {
        if (m.Size == 0) {
            continue;
        }
        if (addr >= m.Base && addr < m.Base + m.Size) {
            return std::string(m.Name.begin(), m.Name.end());
        }
    }
    return {};
}

void FillStatus(google::protobuf::Message* msg, const std::string& err)
{
    // Two response shapes exist:
    //   1. bare OpStatus (Detach, Suspend, Resume, KillProcess, ...): the
    //      message IS the status
    //   2. wrapper responses with an embedded OpStatus at field 0
    // Blindly MutableMessage-ing field 0 on shape 1 hit a CPPTYPE_BOOL field
    // and protobuf aborted the whole agent (FAST_FAIL_FATAL_APP_EXIT).
    auto* d = msg->GetDescriptor();
    auto* refl = msg->GetReflection();
    suspex::OpStatus* st = nullptr;
    if (d->name() == "OpStatus") {
        st = static_cast<suspex::OpStatus*>(msg);
    } else if (d->field_count() > 0 &&
               d->field(0)->type() == google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
        st = static_cast<suspex::OpStatus*>(refl->MutableMessage(msg, d->field(0)));
    } else {
        OutputDebugStringA("FillStatus: unknown response shape, status not set\n");
        return;
    }
    st->set_ok(err.empty());
    if (!err.empty()) {
        st->set_error(err);
        st->set_errno_code(1);
    }
}

// Phase 6a: split into services_{agent,memory,debug,bp}.cpp.
// The four factory functions live in each of those TUs; this function
// just fans out to them in the original construct-then-register order.
void RegisterCoreServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec, host::NetPinMgr& netPin)
{
    (void)exec; // reserved for future core services; unused today
    RegisterAgentSvc(builder, cfg, drv);
    RegisterNetPinSvc(builder, cfg, netPin);
    RegisterMemorySvc(builder, cfg, drv);
    RegisterDebugSvc(builder, cfg, drv);
    RegisterBpSvc(builder, cfg, drv);
}

} // namespace suspex
