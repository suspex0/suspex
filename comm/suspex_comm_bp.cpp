// suspex_comm breakpoints: SW (INT3 patch), HW (DR0-DR3 per-thread), listing.
// Split from suspex_comm.cpp (Phase 7c).
#include "suspex_comm_internal.hpp"

#include <cstddef>
#include <vector>

namespace suspex {

bool Driver::BpSwSet(UINT32 pid, UINT64 addr, UINT32* id, UCHAR* origByte)
{
    SUSPEX_BP_SW_SET_IN in{pid, addr};
    SUSPEX_BP_SW_SET_OUT out{};
    if (!Call(SUSPEX_IOCTL_BP_SW_SET, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_SW_SET", out.Status);
    }
    *id = out.Id;
    *origByte = out.OrigByte;
    return true;
}

bool Driver::BpSwClear(UINT32 pid, UINT64 addr, UINT32 id)
{
    SUSPEX_BP_SW_CLEAR_IN in{pid, addr, id, 0};
    SUSPEX_USER_FREE_OUT out{};
    if (!Call(SUSPEX_IOCTL_BP_SW_CLEAR, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_SW_CLEAR", out.Status);
    }
    return true;
}

bool Driver::BpHwSet(UINT32 pid, UINT64 tid, UINT64 addr, UINT32 slot, UINT32 len, UINT32 access,
                     UINT32* id, UINT32* patched, UINT32 flags)
{
    SUSPEX_BP_HW_SET_IN in{pid, tid, addr, slot, len, access, flags};
    SUSPEX_BP_HW_SET_OUT out{};
    if (!Call(SUSPEX_IOCTL_BP_HW_SET, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_HW_SET", out.Status);
    }
    *id = out.Id;
    *patched = out.ThreadsPatched;
    return true;
}

bool Driver::BpHwClear(UINT32 pid, UINT64 tid, UINT32 slot, UINT32* patched)
{
    SUSPEX_BP_HW_CLEAR_IN in{pid, tid, slot, 0};
    SUSPEX_BP_HW_CLEAR_OUT out{};
    if (!Call(SUSPEX_IOCTL_BP_HW_CLEAR, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_HW_CLEAR", out.Status);
    }
    *patched = out.ThreadsPatched;
    return true;
}

bool Driver::BpList(std::vector<BpRecord>& out)
{
    UINT32 capacity = SUSPEX_MAX_BP;
    for (;;) {
        std::vector<BYTE> buf(sizeof(SUSPEX_BP_LIST_HDR) + (size_t)capacity * sizeof(SUSPEX_BP_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(SUSPEX_IOCTL_BP_LIST, nullptr, 0, buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<SUSPEX_BP_LIST_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW) {
            return FailNt("BP_LIST", hdr->Status);
        }
        if (hdr->Status == SUSPEX_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            capacity = hdr->Required;
            continue;
        }
        auto* e = reinterpret_cast<SUSPEX_BP_ENTRY*>(buf.data() + sizeof(SUSPEX_BP_LIST_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            out.push_back({e[i].Id, e[i].Kind, e[i].Pid, e[i].Tid, e[i].Slot,
                           e[i].Length, e[i].Access, e[i].Enabled, e[i].Address, e[i].OrigByte});
        }
        return true;
    }
}

} // namespace suspex
