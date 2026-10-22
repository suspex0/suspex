// Shared declarations for the drv_exerciser TUs. Split from the original
// monolithic drv_exerciser.cpp (see .kilo/plans/2026-09-17-modular-split.md
// phase 7d). No logic changes: file-scope `static` had to drop for cross-TU
// callers; internal linkage otherwise preserved via anonymous-namespace helpers
// where used.

#pragma once

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "suspex_comm.h"

// Global driver handle (defined in drv_exerciser.cpp).
extern suspex::Driver g_drv;

// Shared helpers defined in cmd_ctx.cpp.
DWORD SpawnProbeThread(HANDLE* outHandle);
UINT64 DrSlot(const CONTEXT* c, UINT32 slot);
bool CtxGetUntil(UINT32 tid, ULONG flags, CONTEXT* ctx, UINT32 slot,
                 UINT64 want, UINT64 wantDr7, UINT64 wantDr7Mask);
__declspec(noinline) void HitTarget(void);

// Command entrypoints — memory / process / kernel-alloc (cmd_mem.cpp)
int CmdPing();
int CmdSelftest();
int CmdMemRead(suspex::Space space, UINT32 pid, UINT64 addr, UINT64 size);
int CmdMemWrite(suspex::Space space, UINT32 pid, UINT64 addr, const std::string& hex);
int CmdProcs();
int CmdMods(bool kernel, UINT32 pid, bool wow64);
int CmdPhysOob();
int CmdPhysWrVerify();
int CmdVaTranslate(UINT64 va);
int CmdVad(UINT32 pid);
int CmdHandles(UINT32 pid, bool names);
int CmdKAlloc(UINT64 size, bool free, UINT64 addr);
int CmdRcall(UINT32 pid, UINT64 tid, UINT64 target, bool kernelMode);

// cmd_call.cpp — v13 kernel function call
int CmdKcall(UINT64 target, const std::vector<UINT64>& args, UINT32 timeoutMs, bool force);

// Thread-context (cmd_ctx.cpp)
int CmdCtxGet(UINT64 tid);
int CmdCtxSetRip(UINT64 tid, UINT64 rip);
int CmdCtxSetVerify();

// Breakpoints (cmd_bp.cpp)
int CmdBpSw(UINT32 pid, UINT64 addr, bool set);
int CmdBpHw(UINT32 pid, UINT64 tid, UINT64 addr, UINT32 slot, UINT32 len,
            const char* access, bool set);
int CmdBpHwHit();
int CmdBpHwVerify();
int CmdBpList();

// Watchdog (cmd_watchdog.cpp)
int CmdWdgArm(UINT32 id, UINT32 deadlineMs, UINT64 cookie, const char* label);
int CmdWdgKick(UINT32 id, UINT32 deadlineMs, UINT64 cookie);
int CmdWdgDisarm(UINT32 id);
int CmdWdgList();
int CmdWdgSmoke();
int CmdWdgFire(UINT32 id, UINT32 deadlineMs, bool confirmed);
