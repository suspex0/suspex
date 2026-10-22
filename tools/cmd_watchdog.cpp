// v8 wedge-detector exerciser commands. Split from drv_exerciser.cpp
// (phase 7d). No logic changes.

#include "exerciser_common.hpp"

using namespace suspex;

// Arms an id, kicks it, verifies List reports it, and disarms — the "smoke
// that it isn't going to bugcheck me" path is used by verify_roundtrip.ps1.
// `wdg-fire` (below) deliberately never kicks and waits past the deadline;
// requires --i-know-i-will-bsod to prevent a stray "just testing" from
// crashing a live target.
int CmdWdgArm(UINT32 id, UINT32 deadlineMs, UINT64 cookie, const char* label)
{
    std::string labelStr = label ? label : "";
    if (!g_drv.WatchdogArm(id, deadlineMs, 0 /*default 0xE2*/, 0 /*flags*/,
                            cookie, labelStr)) {
        printf("FAIL wdg-arm: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS wdg-arm id=%u deadline_ms=%u cookie=0x%llx label='%s'\n",
           id, deadlineMs, (unsigned long long)cookie, labelStr.c_str());
    return 0;
}

int CmdWdgKick(UINT32 id, UINT32 deadlineMs, UINT64 cookie)
{
    UINT64 kicks = 0, lastUs = 0, dlUs = 0;
    if (!g_drv.WatchdogKick(id, deadlineMs, cookie, &kicks, &lastUs, &dlUs)) {
        printf("FAIL wdg-kick: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS wdg-kick id=%u kicks=%llu last_kick_us=%llu deadline_us=%llu\n",
           id, (unsigned long long)kicks, (unsigned long long)lastUs,
           (unsigned long long)dlUs);
    return 0;
}

int CmdWdgDisarm(UINT32 id)
{
    if (!g_drv.WatchdogDisarm(id)) {
        printf("FAIL wdg-disarm: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS wdg-disarm id=%u\n", id);
    return 0;
}

int CmdWdgList()
{
    std::vector<WatchdogEntry> entries;
    UINT64 nowUs = 0;
    if (!g_drv.WatchdogList(entries, &nowUs)) {
        printf("FAIL wdg-list: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS wdg-list count=%zu now_us=%llu\n", entries.size(),
           (unsigned long long)nowUs);
    for (auto& e : entries) {
        printf("  id=%u code=0x%x label='%s' cookie=0x%llx kicks=%llu "
               "armed_us=%llu deadline_us=%llu remaining_ms=%lld\n",
               e.Id, e.BugcheckCode, e.Label.c_str(),
               (unsigned long long)e.Cookie, (unsigned long long)e.KickCount,
               (unsigned long long)e.ArmedUs, (unsigned long long)e.DeadlineUs,
               (long long)(e.RemainingUs / 1000));
    }
    return 0;
}

// Smoke path used by verify_roundtrip: arm short, kick, list, disarm. Never
// lets the watchdog fire.
int CmdWdgSmoke()
{
    const UINT32 id = 0xDEAD;
    printf("smoke: arm id=%u deadline=5000ms\n", id);
    if (CmdWdgArm(id, 5000, 0xBEEFULL, "smoke")) return 1;
    Sleep(100);
    printf("smoke: kick\n");
    if (CmdWdgKick(id, 5000, 0)) { CmdWdgDisarm(id); return 1; }
    printf("smoke: list\n");
    if (CmdWdgList()) { CmdWdgDisarm(id); return 1; }
    printf("smoke: disarm\n");
    if (CmdWdgDisarm(id)) return 1;
    printf("PASS wdg-smoke\n");
    return 0;
}

// Intentionally fires the bugcheck. Requires --i-know-i-will-bsod. Arms a
// short deadline then sleeps past it. When the driver fires,
// this process disappears with the rest of the OS.
int CmdWdgFire(UINT32 id, UINT32 deadlineMs, bool confirmed)
{
    if (!confirmed) {
        printf("FAIL wdg-fire: pass --i-know-i-will-bsod to arm this\n"
               "  this WILL KeBugCheckEx(0xE2) the machine and reboot it.\n");
        return 2;
    }
    printf("WARN wdg-fire: arming id=%u deadline_ms=%u — target will bugcheck in ~%ums\n",
           id, deadlineMs, deadlineMs);
    if (!g_drv.WatchdogArm(id, deadlineMs, 0, 0, 0xF17EULL, "fire")) {
        printf("FAIL wdg-fire arm: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    // Sleep well past the deadline so the driver worker fires. This process
    // dies with the OS; the return statement is unreachable in practice.
    Sleep(deadlineMs + 5000);
    printf("FAIL wdg-fire: still alive after deadline+5s (worker not running?)\n");
    return 1;
}
