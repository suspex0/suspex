// Thread-context (GetContext / SetContext / DR verification) commands and the
// worker-thread helpers shared with cmd_bp.cpp. Split from drv_exerciser.cpp
// (phase 7d). No logic changes.

#include "exerciser_common.hpp"

using namespace suspex;

int CmdCtxGet(UINT64 tid)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!g_drv.CtxGet(tid, ctx.ContextFlags, &ctx)) {
        printf("FAIL ctxget: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS ctxget tid=%llu rip=%llx rsp=%llx dr0=%llx dr7=%llx\n",
           (unsigned long long)tid, (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp,
           (unsigned long long)ctx.Dr0, (unsigned long long)ctx.Dr7);
    return 0;
}

int CmdCtxSetRip(UINT64 tid, UINT64 rip)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!g_drv.CtxGet(tid, CONTEXT_CONTROL, &ctx)) {
        printf("FAIL ctxset(get): %s\n", g_drv.LastError().c_str());
        return 1;
    }
    ctx.Rip = rip;
    if (!g_drv.CtxSet(tid, CONTEXT_CONTROL, &ctx)) {
        printf("FAIL ctxset: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS ctxset tid=%llu rip=%llx\n", (unsigned long long)tid, (unsigned long long)rip);
    return 0;
}

// v2 gate: prove CTX_SET actually applies (v1 was a silent no-op). All DR
// roundtrips run on a worker thread (current-thread DR context ops fail).
int CmdCtxSetVerify()
{
    HANDLE worker = nullptr;
    DWORD workerTid = SpawnProbeThread(&worker);
    CONTEXT dr{};
    dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!g_drv.CtxGet(workerTid, CONTEXT_DEBUG_REGISTERS, &dr)) {
        printf("FAIL ctxset-verify(getdr): %s\n", g_drv.LastError().c_str());
        return 1;
    }
    UINT64 origDr0 = dr.Dr0;
    dr.Dr0 = 0xDEADBEEF00;
    if (!g_drv.CtxSet(workerTid, CONTEXT_DEBUG_REGISTERS, &dr)) {
        printf("FAIL ctxset-verify(setdr): %s\n", g_drv.LastError().c_str());
        return 1;
    }
    CONTEXT dr2{};
    dr2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!g_drv.CtxGet(workerTid, CONTEXT_DEBUG_REGISTERS, &dr2)) {
        printf("FAIL ctxset-verify(getdr2): %s\n", g_drv.LastError().c_str());
        return 1;
    }
    bool ok = dr2.Dr0 == 0xDEADBEEF00;
    dr2.Dr0 = origDr0;
    g_drv.CtxSet(workerTid, CONTEXT_DEBUG_REGISTERS, &dr2);
    if (worker) {
        TerminateThread(worker, 0);
        CloseHandle(worker);
    }
    if (!ok) {
        printf("FAIL ctxset-verify: Dr0=%llx expected DEADBEEF00 (set is a no-op!)\n",
               (unsigned long long)dr2.Dr0);
        return 1;
    }
    printf("PASS ctxset-verify (Dr0 set->get roundtrip on worker thread)\n");
    return 0;
}

// DR-context ops cannot target the CURRENT thread (the kernel must suspend
// the thread to snapshot its DRs -> STATUS_UNSUCCESSFUL on self); all bp-hw
// verification runs against a dedicated worker thread instead
DWORD SpawnProbeThread(HANDLE* outHandle)
{
    *outHandle = nullptr;
    struct Ctx { DWORD tid; HANDLE handle; } c{0, nullptr};
    std::thread t([](Ctx* pc) {
        pc->tid = GetCurrentThreadId();
        pc->handle = nullptr;
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                        &pc->handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
        Sleep(15000); // stays alive while the main thread pokes its DRs
    }, &c);
    t.detach();
    while (!c.tid) {
        Sleep(10);
    }
    *outHandle = c.handle;
    return c.tid;
}

// context set/get roundtrips are asynchronous: PsSetContextThread queues a
// kernel APC that applies on the target thread - poll until it lands
UINT64 DrSlot(const CONTEXT* c, UINT32 slot)
{
    return (&c->Dr0)[slot];
}

bool CtxGetUntil(UINT32 tid, ULONG flags, CONTEXT* ctx, UINT32 slot,
                 UINT64 want, UINT64 wantDr7, UINT64 wantDr7Mask)
{
    for (int i = 0; i < 20; i++) {
        Sleep(100);
        RtlZeroMemory(ctx, sizeof(*ctx));
        ctx->ContextFlags = flags;
        if (!g_drv.CtxGet(tid, flags, ctx)) {
            return false;
        }
        if (DrSlot(ctx, slot) == want && (ctx->Dr7 & wantDr7Mask) == wantDr7) {
            return true;
        }
    }
    return false;
}

// hit target for bp-hw-hit: tiny noinline function we set an exec breakpoint on
__declspec(noinline) void HitTarget(void) {}
