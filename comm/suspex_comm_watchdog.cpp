// suspex_comm watchdog: agent arms a deadline the driver bugchecks past on;
// periodic kicks push the deadline out, disarm stops the timer, list snapshots
// currently armed cookies. Split from suspex_comm.cpp (Phase 7c).
#include "suspex_comm_internal.hpp"

#include <cstring>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace suspex {

bool Driver::WatchdogArm(UINT32 id, UINT32 deadlineMs, UINT32 bugcheckCode,
                         UINT32 flags, UINT64 cookie, const std::string& label)
{
    SUSPEX_WDG_ARM_IN in{};
    in.Id = id;
    in.DeadlineMs = deadlineMs;
    in.BugcheckCode = bugcheckCode;
    in.Flags = flags;
    in.Cookie = cookie;
    if (!label.empty()) {
        size_t n = label.size();
        if (n >= SUSPEX_WDG_MAX_LABEL) n = SUSPEX_WDG_MAX_LABEL - 1;
        memcpy(in.Label, label.data(), n);
        in.Label[n] = '\0';
    }
    SUSPEX_WDG_ARM_OUT out{};
    if (!Call(SUSPEX_IOCTL_WATCHDOG_ARM, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("WATCHDOG_ARM", out.Status);
    }
    return true;
}

bool Driver::WatchdogKick(UINT32 id, UINT32 deadlineMs, UINT64 cookie,
                          UINT64* kickCount, UINT64* lastKickUs, UINT64* deadlineUs)
{
    SUSPEX_WDG_KICK_IN in{id, deadlineMs, cookie};
    SUSPEX_WDG_KICK_OUT out{};
    if (!Call(SUSPEX_IOCTL_WATCHDOG_KICK, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("WATCHDOG_KICK", out.Status);
    }
    if (kickCount)  *kickCount  = out.KickCount;
    if (lastKickUs) *lastKickUs = out.LastKickUs;
    if (deadlineUs) *deadlineUs = out.DeadlineUs;
    return true;
}

bool Driver::WatchdogDisarm(UINT32 id)
{
    SUSPEX_WDG_DISARM_IN in{id, 0};
    SUSPEX_WDG_DISARM_OUT out{};
    if (!Call(SUSPEX_IOCTL_WATCHDOG_DISARM, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("WATCHDOG_DISARM", out.Status);
    }
    return true;
}

bool Driver::WatchdogList(std::vector<WatchdogEntry>& out, UINT64* nowUs)
{
    std::vector<BYTE> buf(sizeof(SUSPEX_WDG_LIST_HDR)
                          + (size_t)SUSPEX_WATCHDOG_MAX * sizeof(SUSPEX_WDG_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(SUSPEX_IOCTL_WATCHDOG_LIST, nullptr, 0, buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<SUSPEX_WDG_LIST_HDR*>(buf.data());
    if (hdr->Status != 0) {
        return FailNt("WATCHDOG_LIST", hdr->Status);
    }
    auto* e = reinterpret_cast<SUSPEX_WDG_ENTRY*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        WatchdogEntry w{};
        w.Id           = e[i].Id;
        w.BugcheckCode = e[i].BugcheckCode;
        w.DeadlineUs   = e[i].DeadlineUs;
        w.LastKickUs   = e[i].LastKickUs;
        w.KickCount    = e[i].KickCount;
        w.Cookie       = e[i].Cookie;
        w.ArmedUs      = e[i].ArmedUs;
        e[i].Label[SUSPEX_WDG_MAX_LABEL - 1] = '\0';
        w.Label        = e[i].Label;
        // Signed remaining: negative means the deadline already passed (the
        // worker either fired or is about to; a listing race can catch it).
        w.RemainingUs = (int64_t)(w.DeadlineUs - hdr->NowUs);
        out.push_back(std::move(w));
    }
    if (nowUs) *nowUs = hdr->NowUs;
    return true;
}

} // namespace suspex
