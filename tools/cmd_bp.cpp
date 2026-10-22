// Breakpoint commands (SW int3 + HW DR slots). Split from drv_exerciser.cpp
// (phase 7d). No logic changes.

#include "exerciser_common.hpp"

using namespace suspex;

// Definitive HW-bp liveness test: set an exec breakpoint on the CURRENT thread
// at HitTarget, then call it repeatedly. When the DR is live the thread takes
// an unhandled #DB and the process terminates with STATUS_SINGLE_STEP
// (0x80000004) - run_exe surfaces that exit code as the positive signal.
int CmdBpHwHit()
{
    UINT32 pid = GetCurrentProcessId();
    UINT64 tid = GetCurrentThreadId();
    UINT32 id = 0, patched = 0;
    UINT64 addr = (UINT64)(ULONG_PTR)&HitTarget;
    if (!g_drv.BpHwSet(pid, tid, addr, 0, 1, SUSPEX_HW_EXEC, &id, &patched)) {
        printf("FAIL bp-hw-hit set: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("bp armed at %llx (id %u), calling target in a loop\n",
           (unsigned long long)addr, id);
    for (int i = 0; i < 100000; i++) {
        HitTarget();
        Sleep(0); // syscall boundary: lets queued context APCs deliver
    }
    UINT32 cleared = 0;
    g_drv.BpHwClear(pid, tid, 0, &cleared);
    printf("FAIL bp-hw-hit: breakpoint never fired after 100000 calls\n");
    return 1;
}

int CmdBpHwVerify()
{
    // exercise all four slots against a worker thread: set, verify via CtxGet,
    // clear, verify clean
    UINT32 pid = GetCurrentProcessId();
    HANDLE worker = nullptr;
    DWORD workerTid = SpawnProbeThread(&worker);
    UINT64 addr = 0x7FFF00000000ull; // unmapped marker address (never executed)
    for (UINT32 slot = 0; slot < 4; slot++) {
        UINT32 id = 0, patched = 0;
        if (!g_drv.BpHwSet(pid, workerTid, addr + slot, slot, 1, SUSPEX_HW_EXEC, &id, &patched)) {
            printf("FAIL bp-hw-verify slot %u set: %s\n", slot, g_drv.LastError().c_str());
            return 1;
        }
        CONTEXT ctx{};
        UINT64 wantDr7 = 1ull << slot;
        if (!CtxGetUntil(workerTid, CONTEXT_DEBUG_REGISTERS, &ctx, slot,
                         addr + slot, wantDr7, wantDr7)) {
            printf("FAIL bp-hw-verify slot %u: Dr%u=%llx (want %llx) dr7=%llx\n",
                   slot, slot, (unsigned long long)DrSlot(&ctx, slot),
                   (unsigned long long)(addr + slot), (unsigned long long)ctx.Dr7);
            return 1;
        }
        UINT32 cleared = 0;
        if (!g_drv.BpHwClear(pid, workerTid, slot, &cleared)) {
            printf("FAIL bp-hw-verify slot %u clear: %s\n", slot, g_drv.LastError().c_str());
            return 1;
        }
        if (!CtxGetUntil(workerTid, CONTEXT_DEBUG_REGISTERS, &ctx, slot,
                         0, 0, wantDr7)) {
            printf("FAIL bp-hw-verify slot %u not cleaned: Dr%u=%llx dr7=%llx\n",
                   slot, slot, (unsigned long long)DrSlot(&ctx, slot), (unsigned long long)ctx.Dr7);
            return 1;
        }
    }
    if (worker) {
        TerminateThread(worker, 0);
        CloseHandle(worker);
    }
    printf("PASS bp-hw-verify (slots 0-3 set/verify/clean on worker thread)\n");
    return 0;
}

int CmdBpSw(UINT32 pid, UINT64 addr, bool set)
{
    if (set) {
        UINT32 id = 0;
        UCHAR orig = 0;
        if (!g_drv.BpSwSet(pid, addr, &id, &orig)) {
            printf("FAIL bp-sw-set: %s\n", g_drv.LastError().c_str());
            return 1;
        }
        printf("PASS bp-sw-set id=%u orig=%02x\n", id, orig);
        if (!g_drv.BpSwClear(pid, addr, id)) {
            printf("FAIL bp-sw-clear: %s\n", g_drv.LastError().c_str());
            return 1;
        }
        printf("PASS bp-sw-clear id=%u\n", id);
        return 0;
    }
    UINT32 id = 0;
    if (!g_drv.BpSwClear(pid, addr, 0)) {
        printf("FAIL bp-sw-clear: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS bp-sw-clear\n");
    return 0;
}

int CmdBpHw(UINT32 pid, UINT64 tid, UINT64 addr, UINT32 slot, UINT32 len, const char* access, bool set)
{
    UINT32 acc = SUSPEX_HW_EXEC;
    if (_stricmp(access, "write") == 0) {
        acc = SUSPEX_HW_WRITE;
    } else if (_stricmp(access, "rw") == 0) {
        acc = SUSPEX_HW_RW;
    }
    if (set) {
        UINT32 id = 0, patched = 0;
        if (!g_drv.BpHwSet(pid, tid, addr, slot, len, acc, &id, &patched)) {
            printf("FAIL bp-hw-set: %s\n", g_drv.LastError().c_str());
            return 1;
        }
        printf("PASS bp-hw-set id=%u threads=%u\n", id, patched);
        UINT32 cleared = 0;
        if (!g_drv.BpHwClear(pid, tid, slot, &cleared)) {
            printf("FAIL bp-hw-clear: %s\n", g_drv.LastError().c_str());
            return 1;
        }
        printf("PASS bp-hw-clear threads=%u\n", cleared);
        return 0;
    }
    UINT32 cleared = 0;
    if (!g_drv.BpHwClear(pid, tid, slot, &cleared)) {
        printf("FAIL bp-hw-clear: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS bp-hw-clear threads=%u\n", cleared);
    return 0;
}

int CmdBpList()
{
    std::vector<BpRecord> bps;
    if (!g_drv.BpList(bps)) {
        printf("FAIL bp-list: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    for (auto& b : bps) {
        printf("  id=%u kind=%s pid=%u tid=%u slot=%u addr=%llx\n", b.Id,
               b.Kind == SUSPEX_BP_KIND_HW ? "hw" : "sw", b.Pid, b.Tid, b.Slot,
               (unsigned long long)b.Address);
    }
    printf("PASS bp-list %zu entries\n", bps.size());
    return 0;
}
