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

std::string DbgSession::ReadMem(UINT64 addr, UINT64 len, std::vector<BYTE>* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    out->assign((size_t)len, 0);
    ULONG read = 0;
    if (FAILED(As<IDebugDataSpaces4>(&spaces4_)->ReadVirtual(addr, out->data(), (ULONG)len, &read))) {
        return "ReadVirtual failed";
    }
    out->resize(read);
    return "";
    });
}

std::string DbgSession::WriteMem(UINT64 addr, const void* data, size_t len)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    ULONG written = 0;
    if (FAILED(As<IDebugDataSpaces4>(&spaces4_)->WriteVirtual(addr, (PVOID)data, (ULONG)len, &written))) {
        return "WriteVirtual failed";
    }
    return "";
    });
}

std::string DbgSession::Regions(std::vector<RegionRec>* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    auto spaces = As<IDebugDataSpaces4>(&spaces4_);
    auto symbols = As<IDebugSymbols3>(&symbols3_);
    MEMORY_BASIC_INFORMATION64 mbi{};
    ULONG64 addr = 0;
    char name[512];
    for (int guard = 0; guard < 100000; guard++) {
        if (FAILED(spaces->QueryVirtual(addr, &mbi))) {
            break;
        }
        RegionRec r;
        r.base = mbi.BaseAddress;
        r.size = mbi.RegionSize;
        r.state = (UINT32)mbi.State;
        r.protect = (UINT32)mbi.Protect;
        r.type = (UINT32)mbi.Type;
        ULONG index = 0;
        ULONG64 modBase = 0;
        if (mbi.State == MEM_COMMIT &&
            SUCCEEDED(symbols->GetModuleByOffset(addr, 0, &index, &modBase)) &&
            SUCCEEDED(symbols->GetModuleNameString(DEBUG_MODNAME_MODULE, index, modBase, name,
                                                   sizeof(name), nullptr))) {
            r.module = name;
        }
        out->push_back(r);
        addr = mbi.BaseAddress + mbi.RegionSize;
        if (addr > 0x7FFFFFFEFFFFull) {
            break;
        }
    }
    return "";
    });
}

} // namespace suspex
