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

std::string DbgSession::BpAdd(bool hw, UINT64 addr, UINT32 size, const std::string& access, UINT32* id)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    // dbgeng rejects bp ops on a running target (E_UNEXPECTED): do a
    // transparent break → arm → resume so the caller never sees it.
    bool wasRunning = !stopped_;
    if (wasRunning) {
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
    }
    auto control = As<IDebugControl4>(&control4_);
    IDebugBreakpoint2* bp = nullptr;
    HRESULT hr = control->AddBreakpoint2(hw ? DEBUG_BREAKPOINT_DATA : DEBUG_BREAKPOINT_CODE,
                                         DEBUG_ANY_ID, &bp);
    if (FAILED(hr)) {
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "AddBreakpoint2 failed hr=" + std::to_string(hr);
    }
    bp->SetOffset(addr);
    if (hw) {
        ULONG acc = DEBUG_BREAK_EXECUTE;
        if (access == "write") {
            acc = DEBUG_BREAK_WRITE;
        } else if (access == "rw") {
            acc = DEBUG_BREAK_READ | DEBUG_BREAK_WRITE;
        } else if (access == "read") {
            acc = DEBUG_BREAK_READ;
        }
        bp->SetDataParameters(size ? size : 1, acc);
    }
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
    ULONG bpId = DEBUG_ANY_ID;
    bp->GetId(&bpId);
    *id = bpId;
    bpIds_.push_back(bpId);
    if (wasRunning) {
        ResumeAfterInterrupt();
    }
    return "";
    });
}

void* DbgSession::FindBpLocked(UINT32 id)
{
    auto control = As<IDebugControl4>(&control4_);
    for (UINT32 known : bpIds_) {
        if (known != id) {
            continue;
        }
        IDebugBreakpoint2* bp = nullptr;
        if (SUCCEEDED(control->GetBreakpointById2(id, &bp))) {
            return bp;
        }
        break;
    }
    return nullptr;
}

std::string DbgSession::BpRemove(UINT32 id)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    bool wasRunning = !stopped_;
    if (wasRunning) {
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
    }
    IDebugBreakpoint2* bp = nullptr;
    if (FAILED(As<IDebugControl4>(&control4_)->GetBreakpointById2(id, &bp))) {
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "breakpoint not found: " + std::to_string(id);
    }
    As<IDebugControl4>(&control4_)->RemoveBreakpoint2(bp);
    if (wasRunning) {
        ResumeAfterInterrupt();
    }
    return "";
    });
}

std::string DbgSession::BpList(std::vector<BpInfoRec>* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    auto control = As<IDebugControl4>(&control4_);
    for (UINT32 id : bpIds_) {
        IDebugBreakpoint2* bp = nullptr;
        if (FAILED(control->GetBreakpointById2(id, &bp))) {
            continue;
        }
        BpInfoRec info;
        info.id = id;
        ULONG64 off = 0;
        bp->GetOffset(&off);
        info.address = off;
        ULONG flags = 0;
        bp->GetFlags(&flags);
        info.enabled = (flags & DEBUG_BREAKPOINT_ENABLED) != 0;
        // both GetType out-params are required; passing nullptr AVs the process
        ULONG type = 0, procType = 0;
        bp->GetType(&type, &procType);
        info.kind = type == DEBUG_BREAKPOINT_DATA ? "hw" : "sw";
        if (type == DEBUG_BREAKPOINT_DATA) {
            ULONG size = 0, acc = 0;
            bp->GetDataParameters(&size, &acc);
            info.access = acc & DEBUG_BREAK_WRITE
                              ? ((acc & DEBUG_BREAK_READ) ? "rw" : "write")
                              : (acc & DEBUG_BREAK_READ ? "read" : "exec");
        }
        out->push_back(info);
        bp->Release();
    }
    return "";
    });
}

std::string DbgSession::BpSetEnabled(UINT32 id, bool enabled)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    bool wasRunning = !stopped_;
    if (wasRunning) {
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
    }
    IDebugBreakpoint2* bp = nullptr;
    if (FAILED(As<IDebugControl4>(&control4_)->GetBreakpointById2(id, &bp))) {
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "breakpoint not found: " + std::to_string(id);
    }
    if (enabled) {
        bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);
    } else {
        bp->RemoveFlags(DEBUG_BREAKPOINT_ENABLED);
    }
    if (wasRunning) {
        ResumeAfterInterrupt();
    }
    return "";
    });
}

} // namespace suspex
