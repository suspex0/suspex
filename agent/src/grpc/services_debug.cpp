#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "suspex.grpc.pb.h"
#include "suspex_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
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

// ------------------------------------------------------------- Debug svc ----

class DebugSvc final : public Debug::Service {
public:
    DebugSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Launch(::grpc::ServerContext* ctx, const LaunchRequest* req, LaunchResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT32 pid = 0, tid = 0;
        std::string err = DbgSession::Instance().Launch(req->cmdline(), req->working_dir(),
                                                        req->break_on_entry(), &pid, &tid);
        FillStatus(resp, err);
        resp->set_pid(pid);
        resp->set_initial_tid(tid);
        return grpc::Status::OK;
    }

    grpc::Status Attach(::grpc::ServerContext* ctx, const AttachRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, DbgSession::Instance().Attach(req->pid(), req->monitor()));
        return grpc::Status::OK;
    }

    grpc::Status Detach(::grpc::ServerContext* ctx, const DetachRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, DbgSession::Instance().Detach(req->kill()));
        return grpc::Status::OK;
    }

    grpc::Status Continue(::grpc::ServerContext* ctx, const ContinueRequest*, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, DbgSession::Instance().Continue());
        return grpc::Status::OK;
    }

    grpc::Status Step(::grpc::ServerContext* ctx, const StepRequest* req, StepResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, DbgSession::Instance().Step(req->kind() == StepRequest::STEP_OVER,
                                                     req->count() ? req->count() : 1));
        return grpc::Status::OK;
    }

    grpc::Status GetRegs(::grpc::ServerContext* ctx, const GetRegsRequest*, GetRegsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        RegsRec r{};
        std::string err = DbgSession::Instance().GetRegs(&r);
        if (err.empty()) {
            auto* rg = resp->mutable_regs();
            rg->set_rax(r.rax);
            rg->set_rcx(r.rcx);
            rg->set_rdx(r.rdx);
            rg->set_rbx(r.rbx);
            rg->set_rsp(r.rsp);
            rg->set_rbp(r.rbp);
            rg->set_rsi(r.rsi);
            rg->set_rdi(r.rdi);
            rg->set_r8(r.r8);
            rg->set_r9(r.r9);
            rg->set_r10(r.r10);
            rg->set_r11(r.r11);
            rg->set_r12(r.r12);
            rg->set_r13(r.r13);
            rg->set_r14(r.r14);
            rg->set_r15(r.r15);
            rg->set_rip(r.rip);
            rg->set_rflags(r.rflags);
            rg->set_dr0((UINT32)r.dr0);
            rg->set_dr1((UINT32)r.dr1);
            rg->set_dr2((UINT32)r.dr2);
            rg->set_dr3((UINT32)r.dr3);
            rg->set_dr6((UINT32)r.dr6);
            rg->set_dr7((UINT32)r.dr7);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status SetRegs(::grpc::ServerContext* ctx, const SetRegsRequest* req, SetRegsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        RegsRec r{};
        const auto& rg = req->regs();
        r.rax = rg.rax(); r.rcx = rg.rcx(); r.rdx = rg.rdx(); r.rbx = rg.rbx();
        r.rsp = rg.rsp(); r.rbp = rg.rbp(); r.rsi = rg.rsi(); r.rdi = rg.rdi();
        r.r8 = rg.r8(); r.r9 = rg.r9(); r.r10 = rg.r10(); r.r11 = rg.r11();
        r.r12 = rg.r12(); r.r13 = rg.r13(); r.r14 = rg.r14(); r.r15 = rg.r15();
        r.rip = rg.rip();
        r.rflags = rg.rflags();
        r.dr0 = rg.dr0(); r.dr1 = rg.dr1(); r.dr2 = rg.dr2(); r.dr3 = rg.dr3();
        r.dr6 = rg.dr6(); r.dr7 = rg.dr7();
        FillStatus(resp, DbgSession::Instance().SetRegs(r, req->apply_gprs(), req->apply_rip(),
                                                        req->apply_rflags(), req->apply_dr()));
        return grpc::Status::OK;
    }

    grpc::Status GetThreads(::grpc::ServerContext* ctx, const GetThreadsRequest*, GetThreadsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<ThreadRec> threads;
        UINT32 cur = 0;
        std::string err = DbgSession::Instance().GetThreads(&threads, &cur);
        for (auto& t : threads) {
            auto* ti = resp->add_threads();
            ti->set_tid(t.tid);
            ti->set_teb(t.teb);
            ti->set_start_address(t.start);
        }
        resp->set_current_tid(cur);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Stacktrace(::grpc::ServerContext* ctx, const StacktraceRequest* req, StacktraceResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<StackFrameRec> frames;
        std::string err = DbgSession::Instance().Stacktrace(req->max_frames() ? req->max_frames() : 32, &frames);
        for (auto& f : frames) {
            auto* sf = resp->add_frames();
            sf->set_frame(f.frame);
            sf->set_return_address(f.ret);
            sf->set_symbol(f.symbol);
            sf->set_displacement(f.displacement);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ReadMemory(::grpc::ServerContext* ctx, const DebugReadRequest* req, DebugReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<BYTE> data;
        std::string err = DbgSession::Instance().ReadMem(req->address(), req->size(), &data);
        if (err.empty()) {
            resp->set_data(data.data(), data.size());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status WriteMemory(::grpc::ServerContext* ctx, const DebugWriteRequest* req, DebugWriteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, DbgSession::Instance().WriteMem(req->address(), req->data().data(),
                                                         req->data().size()));
        return grpc::Status::OK;
    }

    grpc::Status Regions(::grpc::ServerContext* ctx, const MemoryRegionsRequest* req, MemoryRegionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<RegionRec> regions;
        std::string err = DbgSession::Instance().Regions(&regions);
        // L5 pagination: soft slice after driver fill. limit==0 means no cap.
        const int32_t offset = req->offset() > 0 ? req->offset() : 0;
        const int32_t limit  = req->limit()  > 0 ? req->limit()  : 0;
        const size_t start = static_cast<size_t>(offset);
        const size_t stop  = limit > 0
            ? std::min(regions.size(), start + static_cast<size_t>(limit))
            : regions.size();
        for (size_t i = start; i < stop; ++i) {
            const auto& r = regions[i];
            auto* rr = resp->add_regions();
            rr->set_base(r.base);
            rr->set_size(r.size);
            rr->set_state(r.state);
            rr->set_protect(r.protect);
            rr->set_type(r.type);
            rr->set_module(r.module);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ExecuteCommand(::grpc::ServerContext* ctx, const ExecuteCommandRequest* req,
                                ExecuteCommandResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string output;
        std::string err = DbgSession::Instance().Execute(req->command(), &output);
        resp->set_output(output);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status StreamEvents(::grpc::ServerContext* ctx, const StreamDebugEventsRequest* req,
                              grpc::ServerWriter<DebugEvent>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto& events = DbgSession::Instance().Events();
        UINT64 lastSent = req->from_seq() ? req->from_seq() - 1 : 0;
        if (req->from_seq()) {
            // replay buffered history first (dedupe against live pops below)
            std::deque<DebugEventRec> replay;
            events.SnapshotIf([&](const DebugEventRec& r) { return r.seq >= req->from_seq(); },
                              &replay);
            for (auto& rec : replay) {
                if (!WriteDebugEvent(writer, rec)) {
                    return grpc::Status::OK;
                }
                lastSent = rec.seq;
            }
        }
        DebugEventRec rec;
        while (!ctx->IsCancelled()) {
            if (events.Pop(&rec, std::chrono::seconds(1))) {
                if (rec.seq <= lastSent) {
                    continue; // already replayed from history
                }
                if (!WriteDebugEvent(writer, rec)) {
                    return grpc::Status::OK;
                }
                lastSent = rec.seq;
            }
        }
        return grpc::Status::OK;
    }

private:
    static bool WriteDebugEvent(grpc::ServerWriter<DebugEvent>* writer, const DebugEventRec& rec)
    {
        DebugEvent ev;
        ev.set_seq(rec.seq);
        ev.set_tid(rec.tid);
        ev.set_pid(rec.pid);
        ev.set_address(rec.address);
        ev.set_exception_code(rec.code);
        ev.set_description(rec.desc);
        ev.set_timestamp_unix(rec.ts);
        if (rec.kind == "bp_sw") {
            ev.set_kind(DebugEvent::BREAKPOINT_SW);
        } else if (rec.kind == "bp_hw") {
            ev.set_kind(DebugEvent::BREAKPOINT_HW);
        } else if (rec.kind == "exception") {
            ev.set_kind(DebugEvent::EXCEPTION);
        } else if (rec.kind == "process_exit") {
            ev.set_kind(DebugEvent::PROCESS_EXIT);
        } else if (rec.kind == "thread_create") {
            ev.set_kind(DebugEvent::THREAD_CREATE);
        } else if (rec.kind == "thread_exit") {
            ev.set_kind(DebugEvent::THREAD_EXIT);
        } else if (rec.kind == "module_load") {
            ev.set_kind(DebugEvent::MODULE_LOAD);
        } else {
            ev.set_kind(DebugEvent::SESSION_STATUS);
        }
        return writer->Write(ev);
    }

    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterDebugSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static DebugSvc debugSvc(cfg, drv);
    builder.RegisterService(&debugSvc);
}

} // namespace suspex
