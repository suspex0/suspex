#pragma once

#include <windows.h>

#include "../events.hpp"

#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace suspex {

struct DebugEventRec {
    UINT64 seq = 0;
    std::string kind; // bp_sw | bp_hw | exception | process_exit | thread_create | thread_exit | module_load | session_status
    UINT32 pid = 0;
    UINT32 tid = 0;
    UINT64 address = 0;
    INT32 code = 0;
    std::string desc;
    UINT64 ts = 0;
};

struct RegsRec {
    UINT64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    UINT64 r8, r9, r10, r11, r12, r13, r14, r15;
    UINT64 rip;
    UINT32 rflags;
    UINT64 dr0, dr1, dr2, dr3, dr6, dr7;
};

struct ThreadRec {
    UINT32 tid = 0;
    UINT64 teb = 0;
    UINT64 start = 0;
};

struct StackFrameRec {
    UINT64 frame = 0;
    UINT64 ret = 0;
    std::string symbol;
    UINT64 displacement = 0;
};

struct RegionRec {
    UINT64 base = 0, size = 0;
    UINT32 state = 0, protect = 0, type = 0;
    std::string module;
};

struct BpInfoRec {
    UINT32 id = 0;
    std::string kind; // sw | hw
    UINT64 address = 0;
    std::string access;
    bool enabled = false;
};

// single dbgeng session (single active target per plan)
class DbgSession {
public:
    static DbgSession& Instance();

    std::string Launch(const std::string& cmdline, const std::string& workDir, bool breakOnEntry,
                       UINT32* pid, UINT32* tid);
    std::string Attach(UINT32 pid, bool monitor = false);
    std::string Detach(bool kill);
    std::string Continue();
    std::string Step(bool over, UINT64 count);

    bool IsActive() const { return active_; }
    bool IsStopped() const { return stopped_; }
    bool MonitorMode() const { return monitor_; }
    UINT32 CurrentPid() const { return pid_; }

    std::string GetRegs(RegsRec* out);
    std::string SetRegs(const RegsRec& r, bool applyGprs, bool applyRip, bool applyRflags, bool applyDr);
    std::string GetThreads(std::vector<ThreadRec>* out, UINT32* currentTid);
    std::string Stacktrace(UINT32 maxFrames, std::vector<StackFrameRec>* out);
    std::string ReadMem(UINT64 addr, UINT64 len, std::vector<BYTE>* out);
    std::string WriteMem(UINT64 addr, const void* data, size_t len);
    std::string Regions(std::vector<RegionRec>* out);
    std::string Execute(const std::string& command, std::string* output); // raw dbgeng passthrough

    std::string BpAdd(bool hw, UINT64 addr, UINT32 size, const std::string& access, UINT32* id);
    std::string BpRemove(UINT32 id);
    std::string BpList(std::vector<BpInfoRec>* out);
    std::string BpSetEnabled(UINT32 id, bool enabled);

    EventQueue<DebugEventRec>& Events() { return events_; }
    void Shutdown();

private:
    DbgSession() = default;
    std::string InitEngine();
    void EngineLoop();
    std::string RunOnEngine(std::function<std::string()> f);
    void HandleEventLocked();
    UINT32 SysTidFromEngineIdLocked(ULONG engTid);
    void* FindBpLocked(UINT32 id);
    // engine-thread-only: stop a running debugee (DebugBreakProcess is
    // deterministic — SetInterrupt's "next suspension point" can stall on a
    // quiet target) and resume the state we interrupted (GO_HANDLED for the
    // injected int3 / bp hits, GO_NOT_HANDLED for real exceptions).
    std::string EnsureStopped(UINT32 timeoutMs);
    void ResumeAfterInterrupt();

    void* client5_ = nullptr;   // IDebugClient5
    void* control3_ = nullptr;  // IDebugControl3
    void* control4_ = nullptr;  // IDebugControl4
    void* regs2_ = nullptr;     // IDebugRegisters2
    void* spaces4_ = nullptr;   // IDebugDataSpaces4
    void* sysObj4_ = nullptr;   // IDebugSystemObjects4
    void* symbols3_ = nullptr;  // IDebugSymbols3

    bool engineReady_ = false;
    bool active_ = false;
    bool stopped_ = false;
    // monitor mode (Attach monitor=true): bp_hw/bp_sw/single-step hits
    // auto-resume so observation doesn't freeze the target — the
    // passive fallback for kernel-side bp trapping, which a hypervisor
    // can make impossible (descriptor-table exiting / EPT-RO IDT).
    bool monitor_ = false;
    // outstanding int3 events from OUR DebugBreakProcess injections — the
    // pump must GO_HANDLED them (a foreign int3 passed NOT_HANDLED becomes
    // an unhandled exception and kills the debugee)
    int injectedBreaks_ = 0;
    std::string lastEvKind_;
    INT32 lastEvCode_ = 0;
    UINT32 pid_ = 0;
    UINT64 seq_ = 0;
    std::vector<UINT32> bpIds_; // engine-level breakpoint ids we created

    // single dedicated engine thread: dbgeng on 24H2+ delivers events only to
    // the thread that owns the session - every dbgeng call (create, GO, wait,
    // interact) is serialized onto EngineLoop via RunOnEngine
    std::mutex m_; // guards flags/events shared with RPC-facing accessors
    std::thread engineThread_;
    std::mutex qm_;
    std::condition_variable qcv_;
    std::deque<std::shared_ptr<std::packaged_task<std::string()>>> q_;
    bool qOpen_ = true;
    bool shutdown_ = false;
    EventQueue<DebugEventRec> events_;
};

} // namespace suspex
