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

// -------------------------------------------------------- Breakpoints svc ----

class BpSvc final : public Breakpoints::Service {
public:
    BpSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Add(::grpc::ServerContext* ctx, const BpAddRequest* req, BpAddResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        // v0.9: HW BPs are ALWAYS driver-backed (kernel_target is a
        // display hint from here on). Rationale: DbgEng's hw-BP surface
        // silently drops when the sub-session expires — you get
        // "no active session" hours after the last debug_manage call
        // even though target_manage stays connected. The driver's
        // BpHwSet uses KeStackAttachProcess + per-thread DR context
        // writes and works on any pid (user or kernel), so folding
        // both paths onto it removes the failure class entirely.
        // SW BPs still need DbgEng (int3 patch + exception routing),
        // so those keep the DbgSession path — with an auto-attach on
        // demand and a one-shot rebind on stale-session errors below.
        // via_debugger overrides the driver routing for HW bps: the
        // bp-events debug-port fallback mirrors driver bps as dbgeng
        // data breakpoints so hits surface through the debug port on
        // targets where the kernel int1 hook can't install (hypervisor
        // descriptor-table exiting). AddBreakpoint2 doesn't need a
        // stopped target — safe while a monitor session runs.
        if (req->kind() == BpAddRequest::HW && !req->via_debugger()) {
            UINT32 access = SUSPEX_HW_EXEC;
            if (req->access() == "write") {
                access = SUSPEX_HW_WRITE;
            } else if (req->access() == "rw") {
                access = SUSPEX_HW_RW;
            }
            // v6: global + dangerous_ok pack into the driver's Flags byte.
            UINT32 flags = 0;
            if (req->global()) flags |= SUSPEX_BP_HW_FLAG_GLOBAL;
            if (req->dangerous_ok()) flags |= SUSPEX_BP_HW_FLAG_DANGEROUS_OK;
            // Global mode ignores pid — pass 0 to the driver even if the
            // caller happened to set one.
            UINT32 pid = req->global() ? 0u : req->pid();
            UINT32 bpId = 0, patched = 0;
            if (!drv_.Comm().BpHwSet(pid, req->tid(), req->address(), req->slot(),
                                     req->size() ? req->size() : 1, access,
                                     &bpId, &patched, flags)) {
                err = "driver: " + drv_.Comm().LastError();
            } else {
                resp->set_bp_id(bpId + 1000000);
            }
        } else {
            // SW BP path — auto-attach + rebind protects against the
            // stale-dbgeng-session failure mode. IsActive() is stale-safe:
            // a session that DbgEng dropped internally still shows active_
            // = true on our side, so the first BpAdd may still fail with
            // a dbgeng error; we retry once after a fresh Attach.
            auto& dbg = DbgSession::Instance();
            UINT32 target_pid = req->pid();
            if (!dbg.IsActive() && target_pid != 0) {
                std::string att = dbg.Attach(target_pid);
                if (!att.empty()) {
                    FillStatus(resp, "auto-attach pid=" + std::to_string(target_pid)
                                     + " failed: " + att);
                    return grpc::Status::OK;
                }
                OutputDebugStringA(("[dbg] auto-attached pid="
                                    + std::to_string(target_pid) + "\n").c_str());
            }
            UINT32 bpId = 0;
            err = dbg.BpAdd(req->kind() == BpAddRequest::HW, req->address(),
                            req->size(), req->access(), &bpId);
            const bool stale = err.find("no active session") != std::string::npos
                               || err.find("E_UNEXPECTED") != std::string::npos
                               || err.find("RPC_S_SERVER") != std::string::npos;
            if (stale && target_pid != 0) {
                std::string att = dbg.Attach(target_pid);
                if (att.empty()) {
                    OutputDebugStringA(("[dbg] rebind pid="
                                        + std::to_string(target_pid) + "\n").c_str());
                    err = dbg.BpAdd(req->kind() == BpAddRequest::HW, req->address(),
                                    req->size(), req->access(), &bpId);
                }
            }
            if (err.empty()) {
                resp->set_bp_id(bpId);
            }
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Remove(::grpc::ServerContext* ctx, const BpRemoveRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        if (req->bp_id() >= 1000000) {
            std::vector<BpRecord> bps;
            if (drv_.Comm().BpList(bps)) {
                UINT32 want = req->bp_id() - 1000000;
                bool found = false;
                for (auto& b : bps) {
                    if (b.Id == want) {
                        found = true;
                        UINT32 patched = 0;
                        if (!drv_.Comm().BpHwClear(b.Pid, b.Tid, b.Slot, &patched)) {
                            err = "driver: " + drv_.Comm().LastError();
                        }
                        break;
                    }
                }
                // v0.9.4: idempotent remove. Pre-v0.9.4 raised an error
                // when the registry no longer held the id — but with
                // SuspxOnThreadNotify auto-pruning per-thread entries
                // on thread-exit AND v0.9.2's SuspxBpHwClear soft-
                // succeeding on registry misses, the id is expected
                // to be gone by the time a caller retries after an
                // MCP deadline. Match the driver's idempotence: leave
                // err empty so ok=true, and stash a hint in errno_code
                // (=2 == already_removed; FillStatus uses =1 for the
                // generic-error case) so a retrying caller can still
                // tell "we cleared it just now" apart from "it was
                // already gone."
                if (!found) {
                    resp->set_errno_code(2);
                }
            } else {
                err = "driver: " + drv_.Comm().LastError();
            }
        } else {
            err = DbgSession::Instance().BpRemove(req->bp_id());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status List(::grpc::ServerContext* ctx, const BpListRequest*, BpListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<BpInfoRec> bps;
        std::string err = DbgSession::Instance().BpList(&bps);
        // v0.9.4: the dbgeng session is optional — SW BPs and HW BPs both
        // route through the driver in v0.9+, so a bp_manage list must
        // still succeed after a debug_manage detach or a reconnect that
        // hasn't re-attached the debugger. Swallow the specific "no
        // active session" reply here so the driver-side enumeration
        // below is authoritative; any other DbgSession err still
        // propagates as an error.
        if (err == "no active session") {
            err.clear();
        }
        for (auto& b : bps) {
            auto* e = resp->add_breakpoints();
            e->set_bp_id(b.id);
            e->set_kind(b.kind);
            e->set_address(b.address);
            e->set_access(b.access);
            e->set_enabled(b.enabled);
        }
        if (drv_.Comm().Open()) {
            std::vector<BpRecord> dbps;
            if (drv_.Comm().BpList(dbps)) {
                for (auto& b : dbps) {
                    auto* e = resp->add_breakpoints();
                    e->set_bp_id(b.Id + 1000000);
                    e->set_kind(b.Kind == SUSPEX_BP_KIND_HW ? "hw" : "sw");
                    e->set_address(b.Address);
                    e->set_access(b.Access == SUSPEX_HW_WRITE ? "write"
                                  : b.Access == SUSPEX_HW_RW  ? "rw"
                                                              : "exec");
                    e->set_enabled(b.Enabled != 0);
                    // v12: scope fields — the bp_events debug-port
                    // fallback needs to know which process owns the bp.
                    e->set_pid(b.Pid);
                    e->set_tid(b.Tid);
                    e->set_size(b.Length);
                }
            }
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status SetEnabled(::grpc::ServerContext* ctx, const BpSetEnabledRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        if (req->bp_id() >= 1000000) {
            err = "driver breakpoints are enabled/cleared via remove";
        } else {
            err = DbgSession::Instance().BpSetEnabled(req->bp_id(), req->enabled());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterBpSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static BpSvc bpSvc(cfg, drv);
    builder.RegisterService(&bpSvc);
}

} // namespace suspex
