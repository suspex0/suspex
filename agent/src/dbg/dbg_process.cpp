#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

namespace suspex {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

std::string DbgSession::Launch(const std::string& cmdline, const std::string& workDir,
                               bool breakOnEntry, UINT32* pid, UINT32* tid)
{
    return RunOnEngine([&]() -> std::string {
        std::string err = InitEngine();
        if (!err.empty()) {
            return err;
        }
        auto client = As<IDebugClient5>(&client5_);
        auto control = As<IDebugControl3>(&control3_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        if (active_) {
            return "debug session already active; detach first";
        }
        if (breakOnEntry) {
            control->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
        }
        std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
        mutableCmd.push_back('\0');
        DEBUG_CREATE_PROCESS_OPTIONS opts{};
        opts.CreateFlags = DEBUG_ONLY_THIS_PROCESS;
        HRESULT hr = client->CreateProcess2(0, mutableCmd.data(), &opts, sizeof(opts),
                                            workDir.empty() ? nullptr : workDir.c_str(), nullptr);
        if (FAILED(hr)) {
            return "CreateProcess2 failed hr=" + std::to_string(hr) + " (cmd: " + cmdline + ")";
        }
        hr = control->WaitForEvent(0, 15000);
        if (hr != S_OK) {
            client->EndSession(DEBUG_SESSION_END);
            return "no initial debug event hr=" + std::to_string(hr);
        }
        ULONG sysPid = 0, sysTid = 0;
        sys->GetCurrentProcessSystemId(&sysPid);
        sys->GetCurrentThreadSystemId(&sysTid);
        pid_ = sysPid;
        active_ = true;
        stopped_ = true;
        *pid = sysPid;
        *tid = sysTid;
        seq_++;
        events_.Push({++seq_, "session_status", pid_, sysTid, 0, 0, "launched: " + cmdline, NowUnix()});
        return "";
    });
}

std::string DbgSession::Attach(UINT32 pid, bool monitor)
{
    return RunOnEngine([&]() -> std::string {
        std::string err = InitEngine();
        if (!err.empty()) {
            return err;
        }
        auto client = As<IDebugClient5>(&client5_);
        auto control = As<IDebugControl3>(&control3_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        if (active_) {
            // same-pid re-attach is an upgrade: monitor=true flips the
            // running session into auto-resume mode (the bp-events
            // debug-port bridge attaches onto a session that
            // debug_manage may have launched/attached first). Never a
            // silent downgrade — monitor=false keeps prior state.
            if (pid_ == pid) {
                if (monitor) {
                    monitor_ = true;
                    // upgrading to monitor also resumes a target left
                    // stopped at an un-continued event — otherwise the
                    // engine loop never reaches WaitForEvent and the
                    // debugee stays frozen.
                    if (stopped_) {
                        control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
                        stopped_ = false;
                    }
                }
                return "";
            }
            return "debug session already active; detach first";
        }
        if (FAILED(client->AttachProcess(0, pid, 0))) {
            return "AttachProcess failed";
        }
        if (control->WaitForEvent(0, 15000) != S_OK) {
            client->EndSession(DEBUG_SESSION_END);
            return "no attach event";
        }
        ULONG sysPid = 0, sysTid = 0;
        sys->GetCurrentProcessSystemId(&sysPid);
        sys->GetCurrentThreadSystemId(&sysTid);
        pid_ = sysPid;
        active_ = true;
        stopped_ = true;
        monitor_ = monitor;
        seq_++;
        events_.Push({++seq_, "session_status", pid_, sysTid, 0, 0,
                      monitor ? "attached (monitor)" : "attached", NowUnix()});
        if (monitor_) {
            // never leave the debugee frozen at the attach break —
            // observation mode resumes immediately and the engine loop
            // auto-continues bp hits from here on.
            control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
            stopped_ = false;
        }
        return "";
    });
}

std::string DbgSession::Detach(bool kill)
{
    return RunOnEngine([&]() -> std::string {
        auto client = As<IDebugClient5>(&client5_);
        if (!active_) {
            // no live session: still end any zombie engine state so the next
            // launch starts clean
            if (engineReady_) {
                client->EndSession(DEBUG_SESSION_END);
            }
            return "no active session";
        }
        // Terminate/DetachProcesses does the real work on the target. The
        // agent deaths seen here were the FillStatus reflection bug, not
        // dbgeng. No EndSession afterwards: on 24H2+ builds it can abort the
        // process, and a session with an exited process accepts CreateProcess2.
        if (kill) {
            client->TerminateProcesses();
        } else {
            client->DetachProcesses();
        }
        active_ = false;
        stopped_ = false;
        monitor_ = false;
        pid_ = 0;
        return "";
    });
}

std::string DbgSession::Continue()
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            return stopped_ ? "no active session" : "target not stopped";
        }
        auto control = As<IDebugControl3>(&control3_);
        // GO_HANDLED (not plain GO): the initial-break int3 in
        // ntdll!LdrpDoDebuggerBreak (and any breakpoint exception we handle
        // in the debugger) MUST be marked handled, or the OS re-dispatches
        // the exception into the target's SEH chain and the target loops on
        // the int3 forever. cdb/windbg's default filter tables do this for
        // us; we don't install those, so we do it explicitly.
        HRESULT hr = control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
        if (FAILED(hr)) {
            return "SetExecutionStatus failed hr=" + std::to_string(hr);
        }
        // GO only takes effect when issued from the engine thread; once set,
        // the engine loop's WaitForEvent branch (same thread) observes the
        // next stop and pushes the event.
        stopped_ = false;
        return "";
    });
}

std::string DbgSession::Step(bool over, UINT64 count)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            return stopped_ ? "no active session" : "target not stopped";
        }
        auto control = As<IDebugControl3>(&control3_);
        // dbgeng executes one operation per SetExecutionStatus; each subsequent
        // step completes when WaitForEvent observes the step event.
        // Step_over/Step_into implicitly handle any pending exception (they
        // never re-dispatch the initial break to SEH), so no _HANDLED variant.
        for (UINT64 i = 0; i < count; i++) {
            HRESULT hr = control->SetExecutionStatus(over ? DEBUG_STATUS_STEP_OVER : DEBUG_STATUS_STEP_INTO);
            if (FAILED(hr)) {
                return "SetExecutionStatus failed hr=" + std::to_string(hr);
            }
            stopped_ = false;
            hr = control->WaitForEvent(0, 30000);
            if (hr == S_OK) {
                stopped_ = true;
                HandleEventLocked();
                continue; // next step
            }
            if (hr == S_FALSE) {
                stopped_ = false; // still running (e.g. stepped into a long call)
                return "";
            }
            return "WaitForEvent failed hr=" + std::to_string(hr);
        }
        return "";
    });
}

} // namespace suspex
