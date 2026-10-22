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

std::string DbgSession::GetRegs(RegsRec* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_ || !stopped_) {
        return "target not stopped";
    }
    auto regs = As<IDebugRegisters2>(&regs2_);
    auto get1 = [&](const char* name, UINT64* outVal) -> bool {
        ULONG idx = 0;
        DEBUG_VALUE dv{};
        if (FAILED(regs->GetIndexByName(name, &idx)) || FAILED(regs->GetValue(idx, &dv))) {
            return false;
        }
        *outVal = dv.I64;
        return true;
    };
    const char* names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"};
    UINT64* fields[] = {&out->rax, &out->rcx, &out->rdx, &out->rbx, &out->rsp, &out->rbp,
                        &out->rsi, &out->rdi, &out->r8, &out->r9, &out->r10, &out->r11,
                        &out->r12, &out->r13, &out->r14, &out->r15, &out->rip};
    for (int i = 0; i < 17; i++) {
        if (!get1(names[i], fields[i])) {
            return std::string("cannot read register ") + names[i];
        }
    }
    UINT64 rflags = 0;
    if (!get1("efl", &rflags)) {
        return "cannot read efl";
    }
    out->rflags = (UINT32)rflags;
    if (!get1("dr0", &out->dr0) || !get1("dr1", &out->dr1) || !get1("dr2", &out->dr2) ||
        !get1("dr3", &out->dr3) || !get1("dr6", &out->dr6) || !get1("dr7", &out->dr7)) {
        return "cannot read debug registers";
    }
    return "";
    });
}

std::string DbgSession::SetRegs(const RegsRec& r, bool applyGprs, bool applyRip, bool applyRflags,
                                bool applyDr)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_ || !stopped_) {
        return "target not stopped";
    }
    auto regs = As<IDebugRegisters2>(&regs2_);
    auto set1 = [&](const char* name, UINT64 v) -> HRESULT {
        ULONG idx = 0;
        DEBUG_VALUE dv{};
        dv.I64 = v;
        dv.Type = DEBUG_VALUE_INT64;
        if (FAILED(regs->GetIndexByName(name, &idx))) {
            return E_INVALIDARG;
        }
        return regs->SetValue(idx, &dv);
    };
    if (applyGprs) {
        const char* names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        UINT64 vals[] = {r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi,
                         r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15};
        for (int i = 0; i < 16; i++) {
            if (vals[i] && FAILED(set1(names[i], vals[i]))) {
                return "SetValue failed at " + std::string(names[i]);
            }
        }
    }
    if (applyRip && FAILED(set1("rip", r.rip))) {
        return "SetValue failed at rip";
    }
    if (applyRflags && FAILED(set1("efl", r.rflags))) {
        return "SetValue failed at efl";
    }
    if (applyDr) {
        const char* names[] = {"dr0", "dr1", "dr2", "dr3", "dr6", "dr7"};
        UINT64 vals[] = {r.dr0, r.dr1, r.dr2, r.dr3, r.dr6, r.dr7};
        for (int i = 0; i < 6; i++) {
            if (FAILED(set1(names[i], vals[i]))) {
                return "SetValue failed at " + std::string(names[i]);
            }
        }
    }
    return "";
    });
}

std::string DbgSession::GetThreads(std::vector<ThreadRec>* out, UINT32* currentTid)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    auto sys = As<IDebugSystemObjects4>(&sysObj4_);
    ULONG num = 0, cur = 0;
    if (FAILED(sys->GetNumberThreads(&num))) {
        return "GetNumberThreads failed";
    }
    std::vector<ULONG> eng(num), ids(num);
    if (FAILED(sys->GetThreadIdsByIndex(0, num, eng.data(), ids.data()))) {
        return "GetThreadIdsByIndex failed";
    }
    sys->GetCurrentThreadId(&cur);
    for (ULONG i = 0; i < num; i++) {
        ThreadRec t;
        t.tid = ids[i];
        if (SUCCEEDED(sys->SetCurrentThreadId(eng[i]))) {
            ULONG64 off = 0;
            if (SUCCEEDED(sys->GetCurrentThreadDataOffset(&off))) {
                t.teb = off;
            }
        }
        out->push_back(t);
        if (i == cur) {
            *currentTid = ids[i];
        }
    }
    // restore the engine's current thread so later regs/stack calls act on
    // the event thread, not the last enumerated one
    if (cur < num) {
        sys->SetCurrentThreadId(eng[cur]);
    }
    return "";
    });
}

std::string DbgSession::Stacktrace(UINT32 maxFrames, std::vector<StackFrameRec>* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_ || !stopped_) {
        return "target not stopped";
    }
    std::vector<DEBUG_STACK_FRAME> frames(maxFrames);
    ULONG filled = 0;
    if (FAILED(As<IDebugControl4>(&control4_)->GetStackTrace(0, 0, 0, frames.data(), maxFrames, &filled))) {
        return "GetStackTrace failed";
    }
    char buf[512];
    for (ULONG i = 0; i < filled; i++) {
        StackFrameRec f;
        f.frame = frames[i].FrameOffset;
        f.ret = frames[i].ReturnOffset;
        ULONG sizeNeeded = 0;
        ULONG64 disp = 0;
        if (SUCCEEDED(As<IDebugSymbols3>(&symbols3_)->GetNameByOffset(frames[i].InstructionOffset,
                                                                     buf, sizeof(buf), &sizeNeeded, &disp))) {
            f.symbol = buf;
            f.displacement = disp;
        }
        out->push_back(f);
    }
    return "";
    });
}

} // namespace suspex
