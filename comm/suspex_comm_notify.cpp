// suspex_comm notify + kernel enumeration: agent-side wrappers for the
// v10 notify event ring (SUBSCRIBE/READ/DISABLE/STATS) and the kernel
// object-directory / thread-list walks. Split from the core TUs (v10).
#include "suspex_comm_internal.hpp"

#include <cstring>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace suspex {

bool Driver::NotifySubscribe(UINT32 classes, UINT32 flags, UINT32* registered)
{
    SUSPEX_NOTIFY_SUBSCRIBE_IN in{classes, flags};
    SUSPEX_NOTIFY_SUBSCRIBE_OUT out{};
    if (!Call(SUSPEX_IOCTL_NOTIFY_SUBSCRIBE, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("NOTIFY_SUBSCRIBE", out.Status);
    }
    if (registered) *registered = out.Registered;
    return true;
}

bool Driver::NotifyRead(UINT32 max, std::vector<SuspexEventRec>& out,
                        UINT64* dropped, UINT64* lastSeq)
{
    SUSPEX_NOTIFY_READ_IN in{max, 0};
    std::vector<BYTE> buf(sizeof(SUSPEX_NOTIFY_READ_HDR)
                          + (size_t)SUSPEX_EVT_RING * sizeof(SUSPEX_EVT), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_NOTIFY_READ, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_NOTIFY_READ_HDR*>(buf.data());
    if (hdr->Status != 0) {
        return FailNt("NOTIFY_READ", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_EVT*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        SuspexEventRec ev{};
        ev.Seq       = e[i].Seq;
        ev.TsMs      = e[i].TsMs;
        ev.Kind      = e[i].Kind;
        ev.Pid       = e[i].Pid;
        ev.ParentPid = e[i].ParentPid;
        ev.Tid       = e[i].Tid;
        ev.ImageBase = e[i].ImageBase;
        ev.ImageSize = e[i].ImageSize;
        e[i].Image[SUSPEX_EVT_IMAGE_CCH - 1] = L'\0';
        ev.Image = e[i].Image;
        ev.Address   = e[i].Address;
        ev.Dr6       = e[i].Dr6;
        ev.BpId      = e[i].BpId;
        ev.Slot      = e[i].Slot;
        ev.Access    = e[i].Access;
        ev.Irql      = e[i].Irql;
        out.push_back(std::move(ev));
    }
    if (dropped) *dropped = hdr->Dropped;
    if (lastSeq)  *lastSeq  = hdr->LastSeq;
    return true;
}

bool Driver::NotifyDisable(UINT32* registered)
{
    // DISABLE takes no input; the driver answers with the stats layout so
    // the caller learns what was unregistered in the same round trip.
    SUSPEX_NOTIFY_STATS_OUT out{};
    if (!Call(SUSPEX_IOCTL_NOTIFY_DISABLE, nullptr, 0, &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("NOTIFY_DISABLE", out.Status);
    }
    if (registered) *registered = out.Registered;
    return true;
}

bool Driver::NotifyStats(SuspexNotifyStats* out)
{
    SUSPEX_NOTIFY_STATS_OUT o{};
    if (!Call(SUSPEX_IOCTL_NOTIFY_STATS, nullptr, 0, &o, sizeof(o), nullptr)) {
        return false;
    }
    if (o.Status != 0) {
        return FailNt("NOTIFY_STATS", o.Status);
    }
    out->Registered  = o.Registered;
    out->ProcVariant = o.ProcVariant;
    out->BpTrapMissed = o.BpTrapMissed;
    out->Buffered    = o.Buffered;
    out->Dropped     = o.Dropped;
    out->Seq         = o.Seq;
    out->Total       = o.Total;
    return true;
}

bool Driver::ObjEnum(const std::wstring& path, UINT32 depth, UINT32 maxEntries,
                     std::vector<ObjEntryRec>& out, UINT32* required, UINT32* truncated)
{
    SUSPEX_OBJ_ENUM_IN in{};
    size_t n = path.size();
    if (n >= SUSPEX_OBJ_PATH_CCH) n = SUSPEX_OBJ_PATH_CCH - 1;
    memcpy(in.Path, path.c_str(), n * sizeof(WCHAR));
    in.Depth = depth;
    in.MaxEntries = maxEntries;

    std::vector<BYTE> buf(sizeof(SUSPEX_OBJ_HDR)
                          + (size_t)SUSPEX_OBJ_MAX_ENTRIES * sizeof(SUSPEX_OBJ_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_OBJ_ENUM, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_OBJ_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW) {
        return FailNt("OBJ_ENUM", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_OBJ_ENTRY*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        ObjEntryRec o{};
        e[i].Name[SUSPEX_OBJ_NAME_CCH - 1] = L'\0';
        e[i].TypeName[SUSPEX_OBJ_NAME_CCH - 1] = L'\0';
        o.Name = e[i].Name;
        o.Type = e[i].TypeName;
        o.IsDirectory = e[i].IsDirectory;
        out.push_back(std::move(o));
    }
    if (required)  *required  = hdr->Required;
    if (truncated) *truncated = hdr->Truncated;
    return true;
}

bool Driver::ThreadList(UINT32 pid, std::vector<ThreadRow>& out,
                        UINT32* required)
{
    SUSPEX_THREADLIST_IN in{pid, 0};
    std::vector<BYTE> buf(sizeof(SUSPEX_THREAD_HDR)
                          + (size_t)SUSPEX_THREADLIST_MAX * sizeof(SUSPEX_THREAD_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_THREAD_LIST, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_THREAD_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW) {
        return FailNt("THREAD_LIST", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_THREAD_ENTRY*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        ThreadRow t{};
        t.Tid          = e[i].Tid;
        t.Pid          = e[i].Pid;
        t.State        = e[i].State;
        t.WaitReason   = e[i].WaitReason;
        t.BasePriority = e[i].BasePriority;
        t.Flags        = e[i].Flags;
        t.StartVa      = e[i].StartVa;
        t.Win32StartVa = e[i].Win32StartVa;
        t.Teb          = e[i].Teb;
        out.push_back(std::move(t));
    }
    if (required) *required = hdr->Required;
    return true;
}

// v12: per-CPU IDT dump. Same hdr+rows OUT_DIRECT shape as the other
// kernel enumerations; the driver does the __sidt + KIDTENTRY64 decode.
bool Driver::IdtList(bool allCpus, std::vector<IdtRow>& out,
                     UINT64* idtBase, UINT32* idtLimit)
{
    SUSPEX_IDT_LIST_IN in{allCpus ? 1u : 0u, 0};
    std::vector<BYTE> buf(sizeof(SUSPEX_IDT_LIST_HDR)
                          + (size_t)SUSPEX_IDT_MAX_ENTRIES * sizeof(SUSPEX_IDT_ENTRY_ROW), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_IDT_LIST, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_IDT_LIST_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW) {
        return FailNt("IDT_LIST", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_IDT_ENTRY_ROW*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        IdtRow r{};
        r.Cpu       = e[i].Cpu;
        r.Vector    = e[i].Vector;
        r.HandlerVa = e[i].HandlerVa;
        r.Selector  = e[i].Selector;
        r.Ist       = e[i].Ist;
        r.Dpl       = e[i].Dpl;
        r.Type      = e[i].Type;
        r.Present   = e[i].Present;
        r.IdtBase   = e[i].IdtBase;
        out.push_back(std::move(r));
    }
    if (idtBase)  *idtBase  = hdr->IdtBase;
    if (idtLimit) *idtLimit = hdr->IdtLimit;
    return true;
}

} // namespace suspex
