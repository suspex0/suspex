// suspex_comm context / VM introspection: thread CtxGet/CtxSet, RemoteCall
// injection, VAD + handle enumeration, physical-range map, pool scan and
// VA->PA translate. Split from suspex_comm.cpp (Phase 7c).
#include "suspex_comm_internal.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace suspex {

bool Driver::CtxGet(UINT64 tid, ULONG flags, CONTEXT* ctx)
{
    SUSPEX_CTX_HDR_IN in{tid, flags, 0};
    std::vector<BYTE> buf(sizeof(SUSPEX_CTX_HDR_OUT), 0);
    if (!Call(SUSPEX_IOCTL_CTX_GET, &in, sizeof(in), buf.data(), (ULONG)buf.size(), nullptr)) {
        return false;
    }
    auto* out = reinterpret_cast<SUSPEX_CTX_HDR_OUT*>(buf.data());
    if (out->Status != 0) {
        return FailNt("CTX_GET", out->Status);
    }
    memcpy(ctx, out->Context, sizeof(CONTEXT));
    return true;
}

bool Driver::CtxSet(UINT64 tid, ULONG flags, const CONTEXT* ctx)
{
    // v2 combined input layout: [SUSPEX_CTX_HDR_IN][CONTEXT]
    SUSPEX_CTX_HDR_IN in{tid, flags, 0};
    std::vector<BYTE> combined(sizeof(in) + SUSPEX_CONTEXT_SIZE, 0);
    memcpy(combined.data(), &in, sizeof(in));
    if (ctx) {
        memcpy(combined.data() + sizeof(in), ctx, sizeof(CONTEXT));
    }
    SUSPEX_CTX_HDR_OUT out{};
    if (!Call(SUSPEX_IOCTL_CTX_SET, combined.data(), (ULONG)combined.size(), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("CTX_SET", out.Status);
    }
    return true;
}

bool Driver::RemoteCall(UINT32 pid, UINT64 tid, UINT64 target, UINT64 a1, UINT64 a2, UINT64 a3,
                        UINT32 flags, bool* queued, bool* alerted)
{
    SUSPEX_REMOTE_CALL_IN in{pid, tid, target, a1, a2, a3, flags, 0};
    SUSPEX_REMOTE_CALL_OUT out{};
    if (!Call(SUSPEX_IOCTL_REMOTE_CALL, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("REMOTE_CALL", out.Status);
    }
    *queued = out.Queued != 0;
    *alerted = out.Alerted != 0;
    return true;
}

bool Driver::KernelCall(const SUSPEX_KERNEL_CALL_IN& in, SUSPEX_KERNEL_CALL_OUT* out)
{
    SUSPEX_KERNEL_CALL_OUT res{};
    if (!Call(SUSPEX_IOCTL_KERNEL_CALL, const_cast<SUSPEX_KERNEL_CALL_IN*>(&in), sizeof(in),
              &res, sizeof(res), nullptr)) {
        return false;
    }
    *out = res;
    return true;
}

bool Driver::VadList(UINT32 pid, std::vector<VadRecord>& out)
{
    UINT32 capacity = 64;
    std::vector<BYTE> buf;
    for (;;) {
        SUSPEX_VAD_IN in{pid, 0, 0};
        buf.assign(sizeof(SUSPEX_VAD_HDR) + (size_t)capacity * sizeof(SUSPEX_VAD_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(SUSPEX_IOCTL_VAD_LIST, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<SUSPEX_VAD_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW &&
            hdr->Status != SUSPEX_STATUS_PARTIAL_COPY) {
            return FailNt("VAD_LIST", hdr->Status);
        }
        if (hdr->Status == SUSPEX_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            capacity = hdr->Required;
            continue;
        }
        auto* e = reinterpret_cast<SUSPEX_VAD_ENTRY*>(buf.data() + sizeof(SUSPEX_VAD_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            out.push_back({e[i].StartVA, e[i].EndVA, e[i].Protect, e[i].VadType, e[i].CommitCharge});
        }
        return true;
    }
}

bool Driver::HandleList(UINT32 pid, std::vector<HandleRecord>& out, bool wantNames)
{
    UINT32 capacity = 256;
    std::vector<BYTE> buf;
    for (;;) {
        SUSPEX_HANDLE_IN in{pid, wantNames ? 1u : 0u, 0};
        buf.assign(sizeof(SUSPEX_HANDLE_HDR) + (size_t)capacity * sizeof(SUSPEX_HANDLE_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(SUSPEX_IOCTL_HANDLE_LIST, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<SUSPEX_HANDLE_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != SUSPEX_STATUS_BUFFER_OVERFLOW &&
            hdr->Status != SUSPEX_STATUS_PARTIAL_COPY) {
            return FailNt("HANDLE_LIST", hdr->Status);
        }
        if (hdr->Status == SUSPEX_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            capacity = hdr->Required;
            continue;
        }
        auto* e = reinterpret_cast<SUSPEX_HANDLE_ENTRY*>(buf.data() + sizeof(SUSPEX_HANDLE_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            out.push_back({e[i].Object, e[i].HandleValue, e[i].GrantedAccess, e[i].ObjectTypeIndex,
                           std::wstring(e[i].TypeName), std::wstring(e[i].Name)});
        }
        return true;
    }
}

bool Driver::PhysRanges(std::vector<PhysRange>& out)
{
    std::vector<BYTE> buf(sizeof(SUSPEX_PHYS_RANGES_HDR)
                          + (size_t)SUSPEX_MAX_PHYS_RANGES * sizeof(SUSPEX_PHYS_RANGE_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_PHYS_RANGES, nullptr, 0, buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_PHYS_RANGES_HDR*>(buf.data());
    if (hdr->Status != 0) {
        return FailNt("PHYS_RANGES", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_PHYS_RANGE_ENTRY*>(buf.data() + sizeof(*hdr));
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        out.push_back({e[i].Base, e[i].Size, e[i].Kind});
    }
    return true;
}

bool Driver::PoolScan(const PoolScanOptions& opts, std::vector<PoolBlockInfo>& out,
                      UINT32* required, UINT32* considered,
                      PoolScanTelemetry* telemetry)
{
    if (opts.Pattern.size() > SUSPEX_POOL_PATTERN_MAX
        || opts.Mask.size() > SUSPEX_POOL_PATTERN_MAX
        || (opts.Pattern.size() != opts.Mask.size() && !opts.Mask.empty())
        || opts.ContentSpan > SUSPEX_POOL_CONTENT_SPAN_MAX) {
        return FailNt("POOL_SCAN args", (UINT32)STATUS_INVALID_PARAMETER);
    }
    SUSPEX_POOL_SCAN_IN in{};
    in.TagFilter = opts.TagFilter;
    in.Flags = opts.Flags;
    in.MaxResults = opts.MaxResults;
    in.Offset = opts.Offset;
    in.ContentSpan = opts.ContentSpan;
    in.PatternLen = (UINT32)opts.Pattern.size();
    in.Cursor = opts.Cursor;
    if (!opts.Pattern.empty()) {
        memcpy(in.Pattern, opts.Pattern.data(), opts.Pattern.size());
    }
    if (!opts.Mask.empty()) {
        memcpy(in.Mask, opts.Mask.data(), opts.Mask.size());
    }
    UINT32 capacity = opts.MaxResults ? opts.MaxResults : SUSPEX_POOL_MAX_ENTRIES;
    if (capacity > SUSPEX_POOL_MAX_ENTRIES) capacity = SUSPEX_POOL_MAX_ENTRIES;
    std::vector<BYTE> buf(sizeof(SUSPEX_POOL_HDR)
                          + (size_t)capacity * sizeof(SUSPEX_POOL_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_POOL_SCAN, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_POOL_HDR*>(buf.data());
    if (hdr->Status != 0) {
        return FailNt("POOL_SCAN", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_POOL_ENTRY*>(buf.data() + sizeof(*hdr));
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        out.push_back({e[i].VirtualAddress, e[i].SizeInBytes, e[i].Tag, e[i].NonPaged,
                       e[i].MatchedOffset});
    }
    if (required) *required = hdr->Required;
    if (considered) *considered = hdr->Considered;
    if (telemetry) {
        telemetry->Required = hdr->Required;
        telemetry->Considered = hdr->Considered;
        telemetry->Holes = hdr->Holes;
        telemetry->SpanTruncated = hdr->SpanTruncated;
        telemetry->LastIndex = hdr->LastIndex;
        telemetry->NextCursor = hdr->NextCursor;
    }
    return true;
}

bool Driver::VaTranslate(UINT64 va, UINT64* pa)
{
    return VaTranslateEx(va, 0, 0, pa, nullptr, nullptr);
}

bool Driver::VaTranslateEx(UINT64 va, UINT64 cr3, UINT32 pid, UINT64* pa,
                           UINT32* pageSizeShift, UINT64* usedCr3)
{
    // v12: 24-byte IN satisfies a v11 driver's 16-byte minimum (extra tail
    // ignored -> legacy current-CR3 walk); a v11 driver's 16-byte reply
    // leaves PageSizeShift/Cr3 zeroed (ret < sizeof(out)).
    SUSPEX_VA_TRANSLATE_IN in{};
    in.Va = va;
    in.Cr3 = cr3;
    in.Pid = pid;
    SUSPEX_VA_TRANSLATE_OUT out{};
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_VA_TRANSLATE, &in, sizeof(in), &out, sizeof(out), &ret)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("VA_TRANSLATE", out.Status);
    }
    *pa = out.PhysicalAddress;
    if (pageSizeShift) {
        *pageSizeShift = (ret >= sizeof(out)) ? out.PageSizeShift : 0;
    }
    if (usedCr3) {
        *usedCr3 = (ret >= sizeof(out)) ? out.Cr3 : 0;
    }
    return true;
}

} // namespace suspex
