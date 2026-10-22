// drv_exerciser.exe — one subcommand per IOCTL. Safety gate: every IOCTL must
// pass here before the agent's gRPC surface is wired to it.
//
// Phase 7d modular split: this file is the facade at the original path — it
// owns main/Usage/ArgU64 and the g_drv singleton, and dispatches to the Cmd*
// entrypoints defined in cmd_mem.cpp / cmd_ctx.cpp / cmd_bp.cpp /
// cmd_watchdog.cpp. Shared declarations live in exerciser_common.hpp.

#include "exerciser_common.hpp"

using namespace suspex;

suspex::Driver g_drv;

static void Usage()
{
    printf("drv_exerciser <cmd> [args]\n"
           "  ping\n"
           "  selftest                              alloc/write/read/protect/free on self\n"
           "  memread  --pid N --addr 0xX --size N [--kernel|--phys]\n"
           "  memwrite --pid N --addr 0xX --data aabbcc [--kernel|--phys]\n"
           "  kalloc --size N\n"
           "  kfree  --addr 0xX\n"
           "  mods    [--pid N | --kernel | --wow64]\n"
           "  procs                                 enumerate all processes from kernel\n"
           "  vad     --pid N                       VAD walk of pid\n"
           "  handles --pid N [--names]             handle table of pid\n"
           "  phys_oob                              physical range wrap must be rejected\n"
           "  vatrans --addr 0xX                    VA -> PA page-table walk (v5)\n"
           "  physwr-verify                         v5 physical-write gate: opt-in + read-back on own pool\n"
           "  ctxget  --tid N\n"
           "  ctxset-rip --tid N --addr 0xX   (dangerous: hijacks rip)\n"
           "  ctxset-verify                        Dr0 set->get roundtrip on self\n"
           "  bp-sw   --pid N --addr 0xX     set+clear int3\n"
           "  bp-sw-clear --pid N --addr 0xX\n"
           "  bp-hw   --pid N [--tid N] --addr 0xX --slot 0-3 --len 1|2|4|8 --access exec|write|rw\n"
           "  bp-hw-clear --pid N [--tid N] --slot 0-3\n"
           "  bp-hw-verify                         all 4 slots set/verify/clean on self\n"
           "  bp-list\n"
           "  rcall   --pid N --tid N --target 0xX [--kernel]\n"
            "  kcall   --target 0xX [--arg 0xX ...] [--timeout-ms N] [--force]\n"
           "  wdg-arm   --id N --deadline-ms N [--cookie 0xX] [--label S]\n"
           "  wdg-kick  --id N [--deadline-ms N] [--cookie 0xX]\n"
           "  wdg-disarm --id N\n"
           "  wdg-list\n"
           "  wdg-smoke                             arm+kick+list+disarm on id=0xDEAD\n"
           "  wdg-fire  --id N --deadline-ms N --i-know-i-will-bsod\n"
           "                                        DELIBERATELY BSODs the target\n");
}

static UINT64 ArgU64(int argc, char** argv, int& i, const char* name)
{
    i++;
    if (i >= argc) {
        printf("missing %s\n", name);
        exit(2);
    }
    return strtoull(argv[i], nullptr, 0);
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        Usage();
        return 2;
    }
    std::string cmd = argv[1];

    if (!g_drv.Open()) {
        printf("FAIL open \\\\.\\SuspexDrv: %s (driver loaded? admin shell?)\n", g_drv.LastError().c_str());
        return 1;
    }

    if (cmd == "ping") {
        return CmdPing();
    }
    if (cmd == "selftest") {
        return CmdSelftest();
    }
    if (cmd == "memread" || cmd == "memwrite") {
        Space sp = Space::User;
        UINT32 pid = 0;
        UINT64 addr = 0, size = 0;
        std::string data;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            } else if (!strcmp(argv[i], "--size")) {
                size = ArgU64(argc, argv, i, "--size");
            } else if (!strcmp(argv[i], "--data")) {
                data = argv[++i];
            } else if (!strcmp(argv[i], "--kernel")) {
                sp = Space::Kernel;
            } else if (!strcmp(argv[i], "--phys")) {
                sp = Space::Physical;
            }
        }
        if (cmd == "memread") {
            return CmdMemRead(sp, pid, addr, size ? size : 64);
        }
        return CmdMemWrite(sp, pid, addr, data);
    }
    if (cmd == "kalloc") {
        UINT64 size = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--size")) {
                size = ArgU64(argc, argv, i, "--size");
            }
        }
        return CmdKAlloc(size, false, 0);
    }
    if (cmd == "kfree") {
        UINT64 addr = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            }
        }
        return CmdKAlloc(0, true, addr);
    }
    if (cmd == "procs") {
        return CmdProcs();
    }
    if (cmd == "mods") {
        bool kernel = false, wow64 = false;
        UINT32 pid = GetCurrentProcessId();
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--kernel")) {
                kernel = true;
            } else if (!strcmp(argv[i], "--wow64")) {
                wow64 = true;
            }
        }
        return CmdMods(kernel, pid, wow64);
    }
    if (cmd == "vad") {
        UINT32 pid = GetCurrentProcessId();
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            }
        }
        return CmdVad(pid);
    }
    if (cmd == "handles") {
        UINT32 pid = GetCurrentProcessId();
        bool names = false;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--names")) {
                names = true;
            }
        }
        return CmdHandles(pid, names);
    }
    if (cmd == "phys_oob") {
        return CmdPhysOob();
    }
    if (cmd == "vatrans") {
        UINT64 addr = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            }
        }
        return CmdVaTranslate(addr);
    }
    if (cmd == "physwr-verify") {
        return CmdPhysWrVerify();
    }
    if (cmd == "ctxset-verify") {
        return CmdCtxSetVerify();
    }
    if (cmd == "bp-hw-hit") {
        return CmdBpHwHit();
    }
    if (cmd == "bp-hw-verify") {
        return CmdBpHwVerify();
    }
    if (cmd == "ctxget") {
        UINT64 tid = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--tid")) {
                tid = ArgU64(argc, argv, i, "--tid");
            }
        }
        return CmdCtxGet(tid);
    }
    if (cmd == "ctxset-rip") {
        UINT64 tid = 0, addr = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--tid")) {
                tid = ArgU64(argc, argv, i, "--tid");
            } else if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            }
        }
        return CmdCtxSetRip(tid, addr);
    }
    if (cmd == "bp-sw" || cmd == "bp-sw-clear") {
        UINT32 pid = GetCurrentProcessId();
        UINT64 addr = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            }
        }
        return CmdBpSw(pid, addr, cmd == "bp-sw");
    }
    if (cmd == "bp-hw" || cmd == "bp-hw-clear") {
        UINT32 pid = GetCurrentProcessId();
        UINT64 tid = 0, addr = 0;
        UINT32 slot = 0, len = 1;
        const char* access = "exec";
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--tid")) {
                tid = ArgU64(argc, argv, i, "--tid");
            } else if (!strcmp(argv[i], "--addr")) {
                addr = ArgU64(argc, argv, i, "--addr");
            } else if (!strcmp(argv[i], "--slot")) {
                slot = (UINT32)ArgU64(argc, argv, i, "--slot");
            } else if (!strcmp(argv[i], "--len")) {
                len = (UINT32)ArgU64(argc, argv, i, "--len");
            } else if (!strcmp(argv[i], "--access")) {
                access = argv[++i];
            }
        }
        return CmdBpHw(pid, tid, addr, slot, len, access, cmd == "bp-hw");
    }
    if (cmd == "bp-list") {
        return CmdBpList();
    }
    if (cmd == "rcall") {
        UINT32 pid = 0;
        UINT64 tid = 0, target = 0;
        bool kernelMode = false;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--pid")) {
                pid = (UINT32)ArgU64(argc, argv, i, "--pid");
            } else if (!strcmp(argv[i], "--tid")) {
                tid = ArgU64(argc, argv, i, "--tid");
            } else if (!strcmp(argv[i], "--target")) {
                target = ArgU64(argc, argv, i, "--target");
            } else if (!strcmp(argv[i], "--kernel")) {
                kernelMode = true;
            }
        }
        return CmdRcall(pid, tid, target, kernelMode);
    }
    if (cmd == "kcall") {
        UINT64 target = 0;
        std::vector<UINT64> args;
        UINT32 timeoutMs = 0;
        bool force = false;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--target")) {
                target = ArgU64(argc, argv, i, "--target");
            } else if (!strcmp(argv[i], "--arg")) {
                args.push_back(ArgU64(argc, argv, i, "--arg"));
            } else if (!strcmp(argv[i], "--timeout-ms")) {
                timeoutMs = (UINT32)ArgU64(argc, argv, i, "--timeout-ms");
            } else if (!strcmp(argv[i], "--force")) {
                force = true;
            }
        }
        if (!target) {
            printf("FAIL kcall: --target required\n");
            return 2;
        }
        return CmdKcall(target, args, timeoutMs, force);
    }
    if (cmd == "wdg-arm" || cmd == "wdg-kick" || cmd == "wdg-disarm" ||
        cmd == "wdg-list" || cmd == "wdg-smoke" || cmd == "wdg-fire") {
        UINT32 id = 0;
        UINT32 deadlineMs = 0;
        UINT64 cookie = 0;
        const char* label = "";
        bool confirmed = false;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--id")) {
                id = (UINT32)ArgU64(argc, argv, i, "--id");
            } else if (!strcmp(argv[i], "--deadline-ms")) {
                deadlineMs = (UINT32)ArgU64(argc, argv, i, "--deadline-ms");
            } else if (!strcmp(argv[i], "--cookie")) {
                cookie = ArgU64(argc, argv, i, "--cookie");
            } else if (!strcmp(argv[i], "--label")) {
                label = argv[++i];
            } else if (!strcmp(argv[i], "--i-know-i-will-bsod")) {
                confirmed = true;
            }
        }
        if (cmd == "wdg-arm") {
            if (!id || !deadlineMs) {
                printf("FAIL wdg-arm: --id and --deadline-ms required\n");
                return 2;
            }
            return CmdWdgArm(id, deadlineMs, cookie, label);
        }
        if (cmd == "wdg-kick") {
            if (!id) { printf("FAIL wdg-kick: --id required\n"); return 2; }
            return CmdWdgKick(id, deadlineMs, cookie);
        }
        if (cmd == "wdg-disarm") {
            if (!id) { printf("FAIL wdg-disarm: --id required\n"); return 2; }
            return CmdWdgDisarm(id);
        }
        if (cmd == "wdg-list") {
            return CmdWdgList();
        }
        if (cmd == "wdg-smoke") {
            return CmdWdgSmoke();
        }
        if (cmd == "wdg-fire") {
            if (!id || !deadlineMs) {
                printf("FAIL wdg-fire: --id and --deadline-ms required\n");
                return 2;
            }
            return CmdWdgFire(id, deadlineMs, confirmed);
        }
    }

    Usage();
    return 2;
}
