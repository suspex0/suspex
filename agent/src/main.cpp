#include "src/breadcrumb.hpp"
#include "src/config.hpp"
#include "src/driver_mgr.hpp"
#include "src/exec.hpp"
#include "src/grpc/services.hpp"
#include "src/host/screen_common.hpp"
#include "src/log_ring.hpp"
#include "src/service/service_main.hpp"
#include "src/common.h"

#include "suspex_comm.h"

#include <grpcpp/grpcpp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace suspex;

// v5 breadcrumb hooks — one line of arg summary per IOCTL, cheap to
// compute. Anything more detailed is left to per-service logging.
static uint64_t BreadcrumbPre(unsigned long ioctl, const void* in, unsigned long inSize)
{
    char buf[96];
    _snprintf_s(buf, _TRUNCATE, "ioctl=0x%lx inSize=%lu", (unsigned long)ioctl,
                (unsigned long)inSize);
    return Breadcrumb::OnPre((uint32_t)ioctl, buf);
}
static void BreadcrumbPost(uint64_t token, bool ok, unsigned long gle)
{
    Breadcrumb::OnPost(token, ok ? "ok" : "error", (uint32_t)gle);
}

static int AgentMain(int argc, char** argv)
{
    AgentConfig cfg = AgentConfig::FromArgs(argc, argv);
    if (cfg.token.empty()) {
        fprintf(stderr,
                "suspex_agent %s\nusage: suspex_agent.exe --port 50074 --token <secret> "
                "[--dev] [--driver <path>] [--mapper <path>] [--no-driver-ops] [--allow-delete]\n",
                SUSPEX_AGENT_VERSION);
        return 2;
    }

    // Init breadcrumb before we touch the driver so the first ping shows
    // up in the ring. Failure to init just means no persistent ring —
    // agent still works.
    if (!Breadcrumb::Init()) {
        fprintf(stderr, "breadcrumb: init failed (persistent forensics disabled)\n");
    } else {
        Driver::SetTraceHooks(BreadcrumbPre, BreadcrumbPost);
    }

    // v7: kernel-log rotation policy. Best-effort rotate at startup if the
    // on-disk log already blew past the cap during the previous lifetime;
    // subsequent rotations happen opportunistically before Files.LogTail
    // reads large windows. Path matches DriverEntry's log target.
    LogRing::Configure(L"C:\\Users\\Public\\Desktop\\suspex_kernel.log", 0);
    std::string rot_err;
    LogRing::TryRotate(&rot_err);
    if (!rot_err.empty()) {
        fprintf(stderr, "log_ring: %s\n", rot_err.c_str());
    }

    DriverMgr drvMgr(cfg);
    ExecMgr exec;

    std::string addr = "0.0.0.0:" + std::to_string(cfg.port);
    grpc::ServerBuilder builder;
    builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
    // v14: the sync-server defaults (1 CQ / 2 pollers) meant TWO blocked
    // handlers — a hung RunExe plus a long-poll ConsoleRead, or one
    // LogFollow stream — starved EVERY other RPC on the box. Lift the
    // poller budget so a wedged exec call can't take the agent's whole
    // gRPC surface down with it.
    builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
    builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
    RegisterServices(builder, cfg, drvMgr, exec);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    if (!server) {
        fprintf(stderr, "failed to listen on %s\n", addr.c_str());
        return 1;
    }
    printf("suspex_agent %s listening on %s (auth %s)\n", SUSPEX_AGENT_VERSION, addr.c_str(),
           cfg.token.empty() ? "DISABLED" : "token");
    auto gate = RunDriverGate(drvMgr);
    if (!gate.empty()) {
        printf("driver gate: %s\n", gate.c_str());
    } else {
        PingInfo p{};
        drvMgr.Comm().Ping(&p);
        printf("driver: v%u.%u build %u flags=%x\n", p.VersionMajor, p.VersionMinor, p.NtBuild, p.Flags);
    }
    server->Wait();
    DbgSession::Instance().Shutdown();
    // Force one final flush so an SCM-clean stop preserves the last
    // ops for the next Init() to inspect.
    Breadcrumb::FlushSync();
    return 0;
}

int main(int argc, char** argv)
{
    // v15: --screenshot children are re-launches of this exe inside the user
    // session (CreateProcessAsUserW from the Session-0 service). They must run
    // as a plain process — never through the SCM dispatcher.
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--screenshot")) {
            return suspex::screen::RunScreenWorkerCli(argc, argv);
        }
    }
    bool console = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dev")) {
            console = true;
        }
    }
    return RunAsServiceOrConsole(console, "SuspexAgent", AgentMain, argc, argv);
}
