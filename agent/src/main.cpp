#include "src/breadcrumb.hpp"
#include "src/config.hpp"
#include "src/driver_mgr.hpp"
#include "src/exec.hpp"
#include "src/grpc/services.hpp"
#include "src/host/net_pin.hpp"
#include "src/host/screen_common.hpp"
#include "src/listen_watch.hpp"
#include "src/log_ring.hpp"
#include "src/service/service_main.hpp"
#include "src/srv_log.hpp"
#include "src/common.h"

#include "suspex_comm.h"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
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

static void Usage()
{
    fprintf(stderr,
            "suspex_agent %s\n"
            "usage: suspex_agent.exe --port 50074 --token <secret> [--dev]\n"
            "  [--driver <path>] [--mapper <path>] [--no-driver-ops] [--allow-delete]\n"
            "  [--log <path>] [--log-max-mb <n>]\n"
            "  [--pin-adapter <friendly>] [--pin-address <ipv4>] [--pin-prefix <len>]\n"
            "  [--pin-gateway <ipv4>] [--pin-debounce-ms <n>] [--pin-at-boot-only]\n"
            "  [--pin-hold-marker <path>]\n"
            "service mode: sc create SuspexAgent binPath= \"...\\suspex_agent.exe --port 50074 --token ...\"\n"
            "NEVER wrap in `cmd /c` — stdio pipes nobody drains wedge the accept path.\n",
            SUSPEX_AGENT_VERSION);
}

static int AgentMain(int argc, char** argv)
{
    AgentConfig cfg = AgentConfig::FromArgs(argc, argv);
    if (cfg.token.empty()) {
        Usage();
        return 2;
    }

    // v0.31 Phase 5: rotating log + stdio safety BEFORE anything prints.
    // In service/task context (no --dev) stdout/stderr can be pipes nobody
    // drains; a full pipe blocks the writer — a gRPC event-engine thread
    // in that state is exactly the rig's "process up, port dead" wedge.
    // gRPC's own diagnostics (gpr_log) route into the same file.
    srvlog::Open(cfg.logPath, cfg.logMaxBytes);
    if (!cfg.devConsole) {
        if (srvlog::Enabled()) {
            srvlog::CaptureStderr(); // stdout→NUL, stderr→rotating log
        } else {
            srvlog::RedirectStdioToNul();
        }
    }
    srvlog::Logf("suspex_agent %s starting (pid %lu, port %d, auth token, log %s)",
                 SUSPEX_AGENT_VERSION, (unsigned long)GetCurrentProcessId(), cfg.port,
                 cfg.logPath.empty() ? "(off)" : "on");

    // Init breadcrumb before we touch the driver so the first ping shows
    // up in the ring. Failure to init just means no persistent ring —
    // agent still works.
    if (!Breadcrumb::Init()) {
        srvlog::Logf("breadcrumb: init failed (persistent forensics disabled)");
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
        srvlog::Logf("log_ring: %s", rot_err.c_str());
    }

    DriverMgr drvMgr(cfg);
    ExecMgr exec;

    // v0.31 Phase 2.2: static-IPv4 pin (no-op unless --pin-adapter set).
    // Started before the listener so the adapter carries its pinned
    // address before the first client reconnect attempt.
    host::NetPinMgr netPin(cfg);
    netPin.Start();

    std::string addr = "0.0.0.0:" + std::to_string(cfg.port);

    // Driver gate once per process lifetime — independent of the network.
    auto gate = RunDriverGate(drvMgr);
    if (!gate.empty()) {
        srvlog::Logf("driver gate: %s", gate.c_str());
        printf("driver gate: %s\n", gate.c_str());
    } else {
        PingInfo p{};
        drvMgr.Comm().Ping(&p);
        srvlog::Logf("driver: v%u.%u build %u flags=%x", p.VersionMajor, p.VersionMinor,
                     p.NtBuild, p.Flags);
        printf("driver: v%u.%u build %u flags=%x\n", p.VersionMajor, p.VersionMinor, p.NtBuild,
               p.Flags);
    }

    // v0.31 Phase 5: generation loop. BuildAndStart failures (stale
    // instance still holding the port, transient WSAEADDRINUSE during NIC
    // churn) retry with backoff instead of exiting; the listenwatch probe
    // tears down and rebuilds a wedged listener (process up, port dead).
    // A wedge that comes back within 10 minutes of the previous one means
    // in-process rebind is not recovering it — exit(1) so SCM failure
    // recovery takes over with a fresh process.
    std::atomic<bool> stop_requested{false};
    int wedge_streak = 0;
    uint64_t last_wedge_ms = 0;
    for (int generation = 1;; generation++) {
        std::unique_ptr<grpc::Server> server;
        for (int attempt = 1;; attempt++) {
            grpc::ServerBuilder builder;
            builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
            // v14: the sync-server defaults (1 CQ / 2 pollers) meant TWO blocked
            // handlers — a hung RunExe plus a long-poll ConsoleRead, or one
            // LogFollow stream — starved EVERY other RPC on the box. Lift the
            // poller budget so a wedged exec call can't take the agent's whole
            // gRPC surface down with it.
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
            RegisterServices(builder, cfg, drvMgr, exec, netPin);
            server = builder.BuildAndStart();
            if (server) {
                break;
            }
            // 0.5s, 1s, 2s, 4s, 8s, then 15s steady-state. The usual cause is
            // a stale instance still bound to the port (e.g. started before a
            // NIC flap removed its address) — it dies on its own or via SCM
            // recovery, and then we take the port over.
            DWORD delay = attempt >= 6 ? 15000 : (DWORD)(500 << (attempt - 1));
            srvlog::Logf("listen on %s failed (attempt %d) — retrying in %lu ms",
                         addr.c_str(), attempt, (unsigned long)delay);
            fprintf(stderr, "listen on %s failed (attempt %d) — retrying in %lu ms\n",
                    addr.c_str(), attempt, (unsigned long)delay);
            Sleep(delay);
        }
        srvlog::Logf("suspex_agent %s listening on %s (auth token)%s",
                     SUSPEX_AGENT_VERSION, addr.c_str(),
                     generation > 1 ? " [rebound]" : "");
        printf("suspex_agent %s listening on %s (auth %s)%s\n", SUSPEX_AGENT_VERSION,
               addr.c_str(), cfg.token.empty() ? "DISABLED" : "token",
               generation > 1 ? " [rebound]" : "");

        // Self-test the listener: after 3 dead loopback probes, shutdown
        // with a deadline and let the loop rebuild (fresh socket, dead
        // client connections reaped).
        std::atomic<bool> wedged{false};
        grpc::Server* srv = server.get();
        listenwatch::Watch watch((uint16_t)cfg.port, [srv, &wedged] {
            wedged.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        });
        // SCM STOP (service mode): unwind Wait() and exit the loop cleanly.
        SetServiceStopHook([srv, &stop_requested] {
            stop_requested.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(3));
        });

        server->Wait();

        SetServiceStopHook(nullptr);
        watch.Stop();
        if (stop_requested.load()) {
            srvlog::Logf("stop requested — shutting down");
            break;
        }
        // Wedged listener or an unrequested Wait() return: same class of
        // failure. Rebuild once; if it recurs within 10 minutes, exit so
        // SCM failure recovery takes over with a fresh process.
        uint64_t now = GetTickCount64();
        const char* why = wedged.load() ? "listener wedge confirmed"
                                        : "server Wait() returned unexpectedly";
        if (last_wedge_ms != 0 && now - last_wedge_ms < 10 * 60000ull) {
            wedge_streak++;
        } else {
            wedge_streak = 1;
        }
        last_wedge_ms = now;
        if (wedge_streak >= 2) {
            srvlog::Logf("%s; %dx within 10 min — exiting for SCM restart", why,
                         wedge_streak);
            break;
        }
        srvlog::Logf("%s — rebuilding (generation %d)", why, generation + 1);
        Sleep(1000);
        continue;
    }

    netPin.Stop();
    DbgSession::Instance().Shutdown();
    // Force one final flush so an SCM-clean stop preserves the last
    // ops for the next Init() to inspect.
    Breadcrumb::FlushSync();
    srvlog::Logf(wedge_streak >= 2 ? "suspex_agent exiting after repeated listener wedge"
                                   : "suspex_agent stopped cleanly");
    srvlog::Close();
    return wedge_streak >= 2 ? 1 : 0;
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
