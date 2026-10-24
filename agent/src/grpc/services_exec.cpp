#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "suspex.grpc.pb.h"

#include <algorithm>
#include <functional>
#include "services.hpp"
#include "../common.h"
#include "../files.hpp"
#include "../log_ring.hpp"
#include "../exec/detached.hpp"
#include "../exec/call_user.hpp"

#include <filesystem>
#include <fstream>

namespace suspex {

// --------------------------------------------------------------- Exec svc ----

class ExecSvc final : public Exec::Service {
public:
    ExecSvc(const AgentConfig& cfg, DriverMgr& drv, suspex::ExecMgr& exec)
        : cfg_(cfg), drv_(drv), exec_(exec) {}

    grpc::Status RunExe(::grpc::ServerContext* ctx, const RunExeRequest* req, RunExeResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<std::wstring> args;
        for (auto& a : req->args()) {
            int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), -1, nullptr, 0);
            std::wstring w(n ? n - 1 : 0, L'\0');
            if (n) {
                MultiByteToWideChar(CP_UTF8, 0, a.c_str(), -1, w.data(), n);
            }
            args.push_back(w);
        }
        auto res = exec_.RunExe(Utf8ToWide(req->exe()), args, Utf8ToWide(req->working_dir()),
                                (DWORD)req->timeout_ms(),
                                [ctx] { return ctx->IsCancelled(); });
        resp->set_exit_code(res.exitCode);
        resp->set_stdout_data(res.out.data(), res.out.size());
        resp->set_stderr_data(res.err.data(), res.err.size());
        resp->set_timed_out(res.timedOut ? 1 : 0);
        // v7: a timed-out run means we terminated the child. Surface it so the
        // caller can distinguish "clean deadline expiry with partial stdout"
        // from "child ran to completion". ExecMgr::RunExe already terminates
        // on timeout — exit_code of 0xDEADBEEF is our own kill sentinel.
        resp->set_killed(res.timedOut);
        FillStatus(resp, res.error);
        return grpc::Status::OK;
    }

    // ---- v7 detached execution family --------------------------------------
    grpc::Status RunDetached(::grpc::ServerContext* ctx, const RunDetachedRequest* req,
                             RunDetachedResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        auto h = detached_.Spawn(Utf8ToWide(req->cmdline()),
                                  Utf8ToWide(req->working_dir()),
                                  Utf8ToWide(req->stdout_path()),
                                  Utf8ToWide(req->stderr_path()),
                                  req->hidden_window(), &err);
        if (!h) {
            FillStatus(resp, err.empty() ? "run_detached: spawn failed" : err);
            return grpc::Status::OK;
        }
        resp->set_handle_id(h->id);
        resp->set_pid(h->pid);
        resp->set_stdout_path(WideToUtf8(h->stdout_path));
        resp->set_stderr_path(WideToUtf8(h->stderr_path));
        resp->set_started_ts(h->started_ts);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status DetachedStatus(::grpc::ServerContext* ctx, const DetachedHandleRequest* req,
                                DetachedStatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto h = detached_.Get(req->handle_id());
        if (!h) {
            FillStatus(resp, "detached: unknown handle_id");
            return grpc::Status::OK;
        }
        detached_.Poll(h);
        resp->set_running(h->running);
        resp->set_exit_code(h->exit_code);
        resp->set_exited_ts(h->exited_ts);
        resp->set_pid(h->pid);
        resp->set_stdout_path(WideToUtf8(h->stdout_path));
        resp->set_stderr_path(WideToUtf8(h->stderr_path));
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (GetFileAttributesExW(h->stdout_path.c_str(), GetFileExInfoStandard, &a)) {
            ULARGE_INTEGER u{a.nFileSizeLow, a.nFileSizeHigh};
            resp->set_stdout_size(u.QuadPart);
        }
        if (GetFileAttributesExW(h->stderr_path.c_str(), GetFileExInfoStandard, &a)) {
            ULARGE_INTEGER u{a.nFileSizeLow, a.nFileSizeHigh};
            resp->set_stderr_size(u.QuadPart);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status DetachedTail(::grpc::ServerContext* ctx, const DetachedTailRequest* req,
                              DetachedTailResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto h = detached_.Get(req->handle_id());
        if (!h) {
            FillStatus(resp, "detached: unknown handle_id");
            return grpc::Status::OK;
        }
        uint32_t want = req->bytes() ? req->bytes() : 65536;
        auto rout = LogRing::Tail(h->stdout_path, want, true, false, false);
        if (rout.ok) {
            resp->set_stdout_tail(rout.data.data(), rout.data.size());
            resp->set_stdout_total(rout.total_size);
        }
        if (req->stderr_too()) {
            auto rerr = LogRing::Tail(h->stderr_path, want, true, false, false);
            if (rerr.ok) {
                resp->set_stderr_tail(rerr.data.data(), rerr.data.size());
                resp->set_stderr_total(rerr.total_size);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status DetachedKill(::grpc::ServerContext* ctx, const DetachedHandleRequest* req,
                              OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        detached_.Kill(req->handle_id(), &err);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status RunShell(::grpc::ServerContext* ctx, const RunShellRequest* req, RunShellResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        suspex::RunResult res;
        // v1.0.1 Phase 2.3: when the caller supplied encoded_command and
        // the shell is PowerShell, go through -EncodedCommand. Plain
        // command= still works and is the only path for cmd.exe.
        if (req->shell() == POWERSHELL && !req->encoded_command().empty()) {
            res = exec_.RunShellEncoded(req->encoded_command(),
                                        Utf8ToWide(req->working_dir()),
                                        (DWORD)req->timeout_ms(),
                                        [ctx] { return ctx->IsCancelled(); });
        } else {
            res = exec_.RunShell(req->shell() == POWERSHELL, req->command(),
                                 Utf8ToWide(req->working_dir()), (DWORD)req->timeout_ms(),
                                 [ctx] { return ctx->IsCancelled(); });
        }
        resp->set_exit_code(res.exitCode);
        resp->set_output(res.out.data(), res.out.size());
        if (res.err.size()) {
            resp->mutable_output()->append(reinterpret_cast<const char*>(res.err.data()), res.err.size());
        }
        FillStatus(resp, res.error);
        return grpc::Status::OK;
    }

    grpc::Status StartShell(::grpc::ServerContext* ctx, const StartShellRequest* req, StartShellResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        UINT32 id = exec_.StartShell(req->shell() == POWERSHELL, Utf8ToWide(req->working_dir()), &err);
        resp->set_session_id(id);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ConsoleWrite(::grpc::ServerContext* ctx, const WriteConsoleRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        exec_.WriteShell(req->session_id(), req->input(), &err);
        if (!err.empty() && err == "no such shell session") {
            err = NoShellErr(req->session_id());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ConsoleRead(::grpc::ServerContext* ctx, const ReadConsoleRequest* req, ConsoleData* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto shell = exec_.GetShell(req->session_id());
        if (!shell) {
            FillStatus(resp, NoShellErr(req->session_id()));
            return grpc::Status::OK;
        }
        // v14: long-poll in slices so a client-side cancel (wire deadline)
        // frees this poller instead of pinning it for the whole timeout —
        // two stale 30 s polls used to starve every other exec call.
        ULONGLONG deadline = GetTickCount64() +
            (req->timeout_ms() ? req->timeout_ms() : 1000);
        std::vector<BYTE> data;
        while (!ctx->IsCancelled()) {
            auto slice = std::chrono::milliseconds(250);
            if (shell->queue->Pop(&data, slice)) {
                resp->set_data(data.data(), data.size());
                resp->set_eof(data.empty());
                break;
            }
            if (GetTickCount64() >= deadline) {
                break;
            }
        }
        resp->set_session_id(req->session_id());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ListShells(::grpc::ServerContext* ctx, const ListShellsRequest*,
                            ListShellsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        for (uint32_t id : exec_.ShellIds()) {
            resp->add_session_ids(id);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status StopShell(::grpc::ServerContext* ctx, const ShellSessionRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        exec_.StopShell(req->session_id(), &err);
        if (!err.empty() && err == "no such shell session") {
            err = NoShellErr(req->session_id());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status StreamConsole(::grpc::ServerContext* ctx, const StreamConsoleRequest* req,
                               grpc::ServerWriter<ConsoleData>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto shell = exec_.GetShell(req->session_id());
        if (!shell) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "no such shell session");
        }
        std::vector<BYTE> data;
        while (!ctx->IsCancelled()) {
            if (shell->queue->Pop(&data, std::chrono::seconds(1))) {
                ConsoleData c;
                c.set_session_id(req->session_id());
                if (data.empty()) {
                    c.set_eof(true);
                    writer->Write(c);
                    break;
                }
                c.set_data(data.data(), data.size());
                writer->Write(c);
            }
        }
        return grpc::Status::OK;
    }

    grpc::Status KillProcess(::grpc::ServerContext* ctx, const KillProcessRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, req->pid());
        if (!h) {
            FillStatus(resp, Win32ErrorString("OpenProcess", GetLastError()));
            return grpc::Status::OK;
        }
        BOOL ok = TerminateProcess(h, 1);
        DWORD gle = GetLastError();
        CloseHandle(h);
        FillStatus(resp, ok ? "" : Win32ErrorString("TerminateProcess", gle));
        return grpc::Status::OK;
    }

    grpc::Status Suspend(::grpc::ServerContext* ctx, const PidRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, exec_.Suspend(req->pid()));
        return grpc::Status::OK;
    }

    grpc::Status Resume(::grpc::ServerContext* ctx, const PidRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        FillStatus(resp, exec_.Resume(req->pid()));
        return grpc::Status::OK;
    }

    // v15: call a function in target context and return rax. CALL_USER runs
    // the shared param-block trampoline via a remote thread; CALL_KERNEL
    // dispatches through the driver's work-item thunk (PASSIVE_LEVEL,
    // System context). The orchestrator gates this on
    // security.allow_function_call.
    grpc::Status CallFunction(::grpc::ServerContext* ctx, const CallFunctionRequest* req,
                              CallFunctionResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->target_va() == 0) {
            FillStatus(resp, "call: target_va required");
            return grpc::Status::OK;
        }
        if (req->args_size() > 16) {
            FillStatus(resp, "call: argc>16");
            return grpc::Status::OK;
        }
        std::vector<std::uint64_t> args;
        args.reserve((size_t)req->args_size());
        for (uint64_t a : req->args()) {
            args.push_back(a);
        }

        if (req->space() == CALL_KERNEL) {
            if (!drv_.Comm().IsOpen()) {
                FillStatus(resp, "call: driver absent (kernel calls need the agent+driver view)");
                return grpc::Status::OK;
            }
            std::vector<suspex::ModuleEntry> mods;
            bool inModule = false;
            uint64_t target = req->target_va();
            if (!(req->flags() & (uint64_t)SUSPEX_KC_FLAG_FORCE)) {
                if (drv_.Comm().KernelModules(mods)) {
                    for (const auto& m : mods) {
                        if (target >= m.Base && target < m.Base + m.Size) {
                            inModule = true;
                            break;
                        }
                    }
                }
                if (!inModule) {
                    FillStatus(resp, "call: target outside loaded kernel modules (force to override)");
                    return grpc::Status::OK;
                }
            }
            SUSPEX_KERNEL_CALL_IN in{};
            in.Target = target;
            in.Argc = (uint32_t)args.size();
            for (size_t i = 0; i < args.size(); ++i) {
                in.Args[i] = args[i];
            }
            in.TimeoutMs = req->timeout_ms();
            in.Flags = SUSPEX_KC_FLAG_VALIDATED;
            if (req->flags() & 0x2) {
                in.Flags |= SUSPEX_KC_FLAG_FORCE;
            }
            SUSPEX_KERNEL_CALL_OUT out{};
            if (!drv_.Comm().KernelCall(in, &out)) {
                FillStatus(resp, "call: KernelCall failed: " + drv_.Comm().LastError());
                return grpc::Status::OK;
            }
            resp->set_return_value(out.ReturnValue);
            resp->set_exception(out.Exception != 0);
            resp->set_exception_code(out.ExceptionCode);
            resp->set_timed_out(out.Status == 0x102 /*STATUS_TIMEOUT*/ && !out.Completed);
            FillStatus(resp, out.Status == 0
                                ? ""
                                : "call: kernel status 0x" + Hex32(out.Status));
            return grpc::Status::OK;
        }

        // CALL_USER
        if (!req->pid()) {
            FillStatus(resp, "call: pid required for CALL_USER");
            return grpc::Status::OK;
        }
        CallUserResult r = CallUser((uint32_t)req->pid(), req->target_va(), args,
                                    req->timeout_ms(), (req->flags() & 0x1) != 0);
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
            std::string msg = "call: timed out — thread left running";
            if (r.killed) {
                msg = "call: timed out and killed (kill_on_timeout)";
            } else if (r.stub_va) {
                msg += " (tid=" + std::to_string(r.tid) + ", stub_va=0x" +
                       Hex64(r.stub_va) + "; free via Memory.Free)";
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
    static std::string Hex32(uint32_t v)
    {
        char b[16];
        snprintf(b, sizeof(b), "%08x", v);
        return b;
    }
    static std::string Hex64(uint64_t v)
    {
        char b[24];
        snprintf(b, sizeof(b), "%llx", (unsigned long long)v);
        return b;
    }
    static std::wstring Utf8ToWide(const std::string& s)
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n ? n - 1 : 0, L'\0');
        if (n) {
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
        }
        return w;
    }
    static std::string WideToUtf8(const std::wstring& w)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(n ? n - 1 : 0, '\0');
        if (n) {
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
        }
        return s;
    }
    // "no such shell session" with the live ids attached — a session_id that
    // vanished in transit (arg marshaling) now self-diagnoses in one shot.
    std::string NoShellErr(uint32_t id)
    {
        std::string e = "no such shell session id=" + std::to_string(id) + " (live:";
        auto ids = exec_.ShellIds();
        if (ids.empty()) {
            e += " none";
        }
        for (uint32_t live : ids) {
            e += " " + std::to_string(live);
        }
        e += ")";
        return e;
    }
    const AgentConfig& cfg_;
    DriverMgr& drv_;
    suspex::ExecMgr& exec_;
    DetachedRegistry detached_;
};

// Facade helper: builds the singleton ExecSvc and wires it into the
// ServerBuilder. Called from RegisterFileExecServices in services2.cpp.
void RegisterExecSvcInto(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                         ExecMgr& exec)
{
    static ExecSvc execSvc(cfg, drv, exec);
    builder.RegisterService(&execSvc);
}

} // namespace suspex
