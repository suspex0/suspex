#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

namespace suspex {

typedef HRESULT(WINAPI *PFN_DebugCreate)(_In_ REFIID, _Out_ PVOID*);

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

static PFN_DebugCreate GetDebugCreate()
{
    static PFN_DebugCreate fn = nullptr;
    static bool done = false;
    if (!done) {
        done = true;
        HMODULE h = LoadLibraryW(L"dbgeng.dll");
        if (h) {
            fn = (PFN_DebugCreate)GetProcAddress(h, "DebugCreate");
        }
    }
    return fn;
}

DbgSession& DbgSession::Instance()
{
    static DbgSession s;
    return s;
}

// runs ON the engine thread (called from Launch/Attach tasks)
std::string DbgSession::InitEngine()
{
    if (engineReady_) {
        return "";
    }
    auto create = GetDebugCreate();
    if (!create) {
        return "dbgeng.dll not available";
    }
    HRESULT hr = create(__uuidof(IDebugClient5), &client5_);
    if (FAILED(hr)) {
        return "DebugCreate failed hr=" + std::to_string(hr);
    }
    client5_ ? 0 : 0;
    // query facet interfaces via the client pointer
    auto client = As<IDebugClient5>(&client5_);
    client->QueryInterface(__uuidof(IDebugControl3), &control3_);
    client->QueryInterface(__uuidof(IDebugControl4), &control4_);
    client->QueryInterface(__uuidof(IDebugRegisters2), &regs2_);
    client->QueryInterface(__uuidof(IDebugDataSpaces4), &spaces4_);
    client->QueryInterface(__uuidof(IDebugSystemObjects4), &sysObj4_);
    client->QueryInterface(__uuidof(IDebugSymbols3), &symbols3_);
    if (!control3_ || !regs2_ || !spaces4_ || !sysObj4_ || !symbols3_) {
        return "dbgeng interface query failed";
    }
    engineReady_ = true;
    return "";
}

std::string DbgSession::RunOnEngine(std::function<std::string()> f)
{
    if (!engineThread_.joinable()) {
        engineThread_ = std::thread([this] { EngineLoop(); });
    }
    auto task = std::make_shared<std::packaged_task<std::string()>>(std::move(f));
    std::future<std::string> fut = task->get_future();
    {
        std::lock_guard<std::mutex> lk(qm_);
        if (!qOpen_) {
            return "agent shutting down";
        }
        q_.emplace_back(task);
    }
    qcv_.notify_one();
    return fut.get();
}

void DbgSession::Shutdown()
{
    shutdown_ = true;
    {
        std::lock_guard<std::mutex> lk(qm_);
        qOpen_ = false;
    }
    qcv_.notify_all();
    if (engineThread_.joinable()) {
        engineThread_.join();
    }
    events_.Wake();
}

UINT32 DbgSession::SysTidFromEngineIdLocked(ULONG engTid)
{
    ULONG num = 0;
    if (FAILED(As<IDebugSystemObjects4>(&sysObj4_)->GetNumberThreads(&num)) || !num) {
        return engTid;
    }
    std::vector<ULONG> eng(num), sys(num);
    if (FAILED(As<IDebugSystemObjects4>(&sysObj4_)->GetThreadIdsByIndex(0, num, eng.data(), sys.data()))) {
        return engTid;
    }
    for (ULONG i = 0; i < num; i++) {
        if (eng[i] == engTid) {
            return sys[i];
        }
    }
    return engTid;
}

void DbgSession::HandleEventLocked()
{
    auto control = As<IDebugControl3>(&control3_);
    auto sys = As<IDebugSystemObjects4>(&sysObj4_);

    ULONG type = 0, extraType = 0;
    ULONG engTid = 0, engPid = 0;
    ULONG64 extra = 0;
    ULONG used = 0, textUsed = 0;
    char text[512]{};
    char desc[256]{};

    DEBUG_LAST_EVENT_INFO_EXCEPTION exc{};
    DEBUG_LAST_EVENT_INFO_BREAKPOINT bpInfo{};

    if (FAILED(control->GetLastEventInformation(&type, &engPid, &engTid, &exc, sizeof(exc), &used,
                                                text, sizeof(text), &textUsed))) {
        return;
    }
    UNREFERENCED_PARAMETER(extraType);
    UNREFERENCED_PARAMETER(extra);

    DebugEventRec ev;
    ev.ts = NowUnix();
    ev.tid = SysTidFromEngineIdLocked(engTid);
    ev.pid = pid_;
    switch (type) {
    case DEBUG_EVENT_BREAKPOINT:
        control->GetLastEventInformation(&type, &engPid, &engTid, &bpInfo, sizeof(bpInfo), &used,
                                         nullptr, 0, nullptr);
        {
            ULONG num = 0;
            bool hw = false;
            auto control4 = As<IDebugControl4>(&control4_);
            if (SUCCEEDED(control4->GetNumberBreakpoints(&num)) && num && bpInfo.Id != DEBUG_ANY_ID) {
                IDebugBreakpoint2* bp = nullptr;
                if (SUCCEEDED(control4->GetBreakpointById2(bpInfo.Id, &bp)) && bp) {
                    // both GetType out-params are required; passing nullptr AVs
                    ULONG bpType = 0, procType = 0;
                    bp->GetType(&bpType, &procType);
                    hw = bpType == DEBUG_BREAKPOINT_DATA;
                    // the bp's own offset IS the hit address for exec bps
                    // and the watched address for data bps — far more
                    // useful downstream than the thread data offset.
                    ULONG64 bpOff = 0;
                    if (SUCCEEDED(bp->GetOffset(&bpOff))) {
                        ev.address = bpOff;
                    }
                    bp->Release();
                }
            }
            ev.kind = hw ? "bp_hw" : "bp_sw";
        }
        if (!ev.address) {
            sys->GetCurrentThreadDataOffset(&ev.address);
        }
        break;
    case DEBUG_EVENT_EXCEPTION:
        ev.kind = "exception";
        ev.code = (INT32)exc.ExceptionRecord.ExceptionCode;
        ev.address = exc.ExceptionRecord.ExceptionAddress;
        snprintf(desc, sizeof(desc), "first_chance=%d code=0x%08X",
                 (int)exc.FirstChance, (UINT32)exc.ExceptionRecord.ExceptionCode);
        ev.desc = desc;
        break;
    case DEBUG_EVENT_EXIT_PROCESS:
        ev.kind = "process_exit";
        ev.code = (INT32)((DEBUG_LAST_EVENT_INFO_EXIT_PROCESS*)&exc)->ExitCode;
        active_ = false;
        break;
    case DEBUG_EVENT_CREATE_THREAD:
        ev.kind = "thread_create";
        sys->GetCurrentThreadDataOffset(&ev.address);
        break;
    case DEBUG_EVENT_EXIT_THREAD:
        ev.kind = "thread_exit";
        break;
    case DEBUG_EVENT_LOAD_MODULE:
        ev.kind = "module_load";
        sys->GetCurrentThreadDataOffset(&ev.address);
        break;
    case DEBUG_EVENT_SESSION_STATUS:
        ev.kind = "session_status";
        break;
    default:
        ev.kind = "session_status";
        break;
    }
    if (!ev.desc.empty() || text[0]) {
        ev.desc = ev.desc.empty() ? text : ev.desc + " " + text;
    }
    ev.seq = ++seq_;
    lastEvKind_ = ev.kind;
    lastEvCode_ = ev.code;
    events_.Push(ev);
}

void DbgSession::EngineLoop()
{
    // THE dbgeng thread. On 24H2+ builds event delivery is pinned to the
    // thread that owns the session: DebugCreate, GO, WaitForEvent and every
    // interaction must happen here, serialized through the task queue.
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    for (;;) {
        std::shared_ptr<std::packaged_task<std::string()>> task;
        bool have_task = false;
        {
            std::unique_lock<std::mutex> lk(qm_);
            // timed wait: the queue AND the event pump must both get turns on
            // this thread (an idle wait here would starve WaitForEvent)
            qcv_.wait_for(lk, std::chrono::milliseconds(50),
                          [&] { return !q_.empty() || !qOpen_; });
            if (!q_.empty()) {
                task = q_.front();
                q_.pop_front();
                have_task = true;
            } else if (!qOpen_) {
                break;
            }
        }
        if (have_task) {
            (*task)();
            continue;
        }
        // queue idle: pump debug events while a live session is running
        bool canWait = false;
        {
            std::lock_guard<std::mutex> lk(m_);
            canWait = engineReady_ && active_ && !stopped_;
            if (canWait) {
                HRESULT hr = As<IDebugControl3>(&control3_)->WaitForEvent(0, 100);
                if (hr == S_OK) {
                    stopped_ = true;
                    HandleEventLocked();
                    // monitor mode = passive observation: EVERY event resumes
                    // the debugee — leaving it stopped at an un-continued
                    // thread/module/exit event freezes the process (and wedges
                    // kernel Ps*ContextThread callers waiting on its threads).
                    // bp hits and driver-armed DR single-steps are ours:
                    // GO_HANDLED. Foreign exceptions pass GO_NOT_HANDLED so the
                    // app's own dispatching decides (same as undebugged).
                    if (monitor_ && stopped_) {
                        ULONG st = DEBUG_STATUS_GO;
                        bool foreignStep = false;
                        if (lastEvKind_ == "exception"
                            && lastEvCode_ == (INT32)0x80000003
                            && injectedBreaks_ > 0) {
                            // leftover int3 from our own EnsureStopped
                            // injection — swallow it (NOT_HANDLED would
                            // kill the debugee)
                            injectedBreaks_--;
                            st = DEBUG_STATUS_GO_HANDLED;
                        } else if (lastEvKind_ == "bp_hw" || lastEvKind_ == "bp_sw") {
                            st = DEBUG_STATUS_GO_HANDLED;
                        } else if (lastEvKind_ == "exception"
                                   && lastEvCode_ == (INT32)0x80000004) {
                            st = DEBUG_STATUS_GO_HANDLED;
                            foreignStep = true;
                        } else if (lastEvKind_ == "exception") {
                            st = DEBUG_STATUS_GO_NOT_HANDLED;
                        }
                        if (foreignStep) {
                            // a single-step dbgeng didn't arm (driver DR
                            // state predating the attach, etc.) is a fault
                            // AT rip — resuming without RF refires the #DB
                            // instantly and storms the debug port. Set RF so
                            // the instruction executes once; the bp stays
                            // armed for the next hit.
                            auto regs = As<IDebugRegisters2>(&regs2_);
                            ULONG idx = 0;
                            DEBUG_VALUE dv{};
                            if (SUCCEEDED(regs->GetIndexByName("efl", &idx))
                                && SUCCEEDED(regs->GetValue(idx, &dv))) {
                                dv.I64 |= 0x10000; // EFLAGS.RF
                                dv.Type = DEBUG_VALUE_INT64;
                                regs->SetValue(idx, &dv);
                            }
                        }
                        As<IDebugControl3>(&control3_)->SetExecutionStatus(st);
                        stopped_ = false;
                    }
                }
            }
        }
        if (!canWait) {
            Sleep(50);
        }
    }
    CoUninitialize();
}

// Must run on the engine thread (inside a RunOnEngine task). DebugBreakProcess
// injects an int3 thread — deterministic even on a quiet debugee, where
// SetInterrupt's "next suspension point" semantics can stall indefinitely.
std::string DbgSession::EnsureStopped(UINT32 timeoutMs)
{
    if (stopped_) {
        return "";
    }
    if (!engineReady_ || !active_ || !pid_) {
        return "no active session";
    }
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, pid_);
    if (!h) {
        return "OpenProcess failed gle=" + std::to_string(GetLastError());
    }
    BOOL ok = DebugBreakProcess(h);
    DWORD gle = GetLastError();
    CloseHandle(h);
    if (!ok) {
        return "DebugBreakProcess failed gle=" + std::to_string(gle);
    }
    injectedBreaks_++;
    auto control = As<IDebugControl3>(&control3_);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        HRESULT hr = control->WaitForEvent(0, 200);
        if (hr == S_OK) {
            stopped_ = true;
            HandleEventLocked();
            if (lastEvKind_ == "exception" && lastEvCode_ == (INT32)0x80000003) {
                injectedBreaks_--; // our int3 won the race — consumed
            }
            return "";
        }
    }
    return "interrupt did not stop the target";
}

// Must run on the engine thread. Continues a debugee we interrupted for an
// internal operation: the injected int3 / our bp hits are GO_HANDLED (the
// injected DbgBreakPoint thread must not redispatch — an unhandled int3
// kills the process), foreign single-steps get RF + GO_HANDLED so a stray
// armed DR cannot refire, real exceptions pass GO_NOT_HANDLED.
void DbgSession::ResumeAfterInterrupt()
{
    ULONG st = DEBUG_STATUS_GO;
    bool foreignStep = false;
    if (lastEvKind_ == "exception" && lastEvCode_ == (INT32)0x80000003
        && injectedBreaks_ > 0) {
        injectedBreaks_--;
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "bp_hw" || lastEvKind_ == "bp_sw") {
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "exception"
               && lastEvCode_ == (INT32)0x80000003) {
        // an int3 not ours (real __debugbreak in the debugee) — still
        // HANDLED in the interrupt-resume context so the state restores
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "exception"
               && lastEvCode_ == (INT32)0x80000004) {
        st = DEBUG_STATUS_GO_HANDLED;
        foreignStep = true;
    } else if (lastEvKind_ == "exception") {
        st = DEBUG_STATUS_GO_NOT_HANDLED;
    }
    if (foreignStep) {
        auto regs = As<IDebugRegisters2>(&regs2_);
        ULONG idx = 0;
        DEBUG_VALUE dv{};
        if (SUCCEEDED(regs->GetIndexByName("efl", &idx))
            && SUCCEEDED(regs->GetValue(idx, &dv))) {
            dv.I64 |= 0x10000; // EFLAGS.RF
            dv.Type = DEBUG_VALUE_INT64;
            regs->SetValue(idx, &dv);
        }
    }
    As<IDebugControl3>(&control3_)->SetExecutionStatus(st);
    stopped_ = false;
}

} // namespace suspex
