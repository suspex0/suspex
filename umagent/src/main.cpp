#include "um_services.hpp"
#include "umem.hpp"
#include "srv_log.hpp"
#include "listen_watch.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <windows.h>

int UmMain(int argc, char** argv);

namespace {

void Usage()
{
    fprintf(stderr,
            "suspex_umagent: usermode-only memory/module view (parity cross-check target)\n"
            "usage: suspex_umagent.exe --port 50075 --token <secret> [--bind 127.0.0.1]\n"
            "       [--max-read-mb 8] [--dev] [--log <path>]\n");
}

// ---- minimal SCM wrapper: umagent previously had none, so the service timed
// ---- out (7009) and SCM killed it; same coarse stop semantics as the agent

SERVICE_STATUS g_status{};
SERVICE_STATUS_HANDLE g_handle = nullptr;
int (*g_fn)(int, char**) = nullptr;
int g_argc = 0;
char** g_argv = nullptr;

void SetState(DWORD state, DWORD waitHint = 0)
{
    if (!g_handle) {
        return;
    }
    static DWORD checkpoint = 0;
    g_status.dwCurrentState = state;
    g_status.dwCheckPoint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : ++checkpoint;
    g_status.dwWaitHint = waitHint;
    SetServiceStatus(g_handle, &g_status);
}

DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID)
{
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SetState(SERVICE_STOP_PENDING, 5000);
        SetState(SERVICE_STOPPED);
        ExitProcess(0);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR* argv)
{
    LPCWSTR name = (argv && argv[0]) ? argv[0] : L"SuspexUmagent";
    g_handle = RegisterServiceCtrlHandlerExW(name, ServiceCtrlHandler, nullptr);
    if (!g_handle) {
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetState(SERVICE_START_PENDING, 5000);
    std::thread([] {
        SetState(SERVICE_RUNNING);
        g_fn(g_argc, g_argv);
        SetState(SERVICE_STOPPED);
    }).detach();
}

int RunAsServiceOrConsole(bool console, int (*fn)(int, char**), int argc, char** argv)
{
    if (console) {
        return fn(argc, argv);
    }
    SERVICE_TABLE_ENTRYW table[2]{};
    table[0].lpServiceName = const_cast<LPWSTR>(L"SuspexUmagent");
    table[0].lpServiceProc = ServiceMain;
    g_fn = fn;
    g_argc = argc;
    g_argv = argv;
    if (!StartServiceCtrlDispatcherW(table)) {
        if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return 1;
        }
        return fn(argc, argv);
    }
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool console = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dev")) {
            console = true;
        }
    }
    return RunAsServiceOrConsole(console, UmMain, argc, argv);
}

int UmMain(int argc, char** argv)
{
    um::Config cfg;
    std::wstring logPath;
    bool dev = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            cfg.port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--token") && i + 1 < argc) {
            cfg.token = argv[++i];
        } else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
            cfg.bind = argv[++i];
        } else if (!strcmp(argv[i], "--max-read-mb") && i + 1 < argc) {
            cfg.maxReadBytes = (uint64_t)atoi(argv[++i]) << 20;
        } else if (!strcmp(argv[i], "--dev")) {
            dev = true;
        } else if (!strcmp(argv[i], "--log") && i + 1 < argc) {
            int n = MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, nullptr, 0);
            logPath.resize(n ? n - 1 : 0);
            if (n) {
                MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, logPath.data(), n);
            }
        } else {
            Usage();
            return 2;
        }
    }
    if (cfg.port <= 0) {
        Usage();
        return 2;
    }

    um::EnableDebugPriv(); // best effort: SeDebugPrivilege when run elevated

    // v1.0.1 Phase 5: same stdio/log safety as the agent (see srv_log.hpp).
    suspex::srvlog::Open(logPath);
    if (!dev) {
        if (suspex::srvlog::Enabled()) {
            suspex::srvlog::CaptureStderr(); // stdout→NUL, stderr→rotating log
        } else {
            suspex::srvlog::RedirectStdioToNul();
        }
    }
    suspex::srvlog::Logf("suspex_umagent %s starting (pid %lu)", cfg.version.c_str(),
                         (unsigned long)GetCurrentProcessId());

    // v1.0.1 Phase 5: bind-retry + listener self-test/rebind, same as the
    // agent — the umagent shares every failure mode from the rig report.
    std::string addr = cfg.bind + ":" + std::to_string(cfg.port);
    for (int generation = 1;; generation++) {
        std::unique_ptr<grpc::Server> server;
        for (int attempt = 1;; attempt++) {
            grpc::ServerBuilder builder;
            builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
            // Same fix as the agent: stock sync-server defaults starve the view
            // after two concurrent blocking calls.
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
            um::RegisterServices(builder, cfg);
            server = builder.BuildAndStart();
            if (server) {
                break;
            }
            DWORD delay = attempt >= 6 ? 15000 : (DWORD)(500 << (attempt - 1));
            suspex::srvlog::Logf("listen on %s failed (attempt %d) — retrying in %lu ms",
                                 addr.c_str(), attempt, (unsigned long)delay);
            fprintf(stderr, "listen on %s failed (attempt %d) — retrying in %lu ms\n",
                    addr.c_str(), attempt, (unsigned long)delay);
            Sleep(delay);
        }
        suspex::srvlog::Logf("suspex_umagent %s listening on %s (auth %s)%s",
                             cfg.version.c_str(), addr.c_str(),
                             cfg.token.empty() ? "DISABLED" : "token",
                             generation > 1 ? " [rebound]" : "");
        printf("suspex_umagent %s listening on %s (auth %s)%s\n", cfg.version.c_str(),
               addr.c_str(), cfg.token.empty() ? "DISABLED" : "token",
               generation > 1 ? " [rebound]" : "");
        fflush(stdout);

        std::atomic<bool> wedged{false};
        grpc::Server* srv = server.get();
        suspex::listenwatch::Watch watch((uint16_t)cfg.port, [srv, &wedged] {
            wedged.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        });

        server->Wait();
        watch.Stop();
        if (wedged.load()) {
            suspex::srvlog::Logf("listener wedge confirmed — rebuilding (generation %d)",
                                 generation + 1);
            Sleep(1000);
            continue;
        }
        suspex::srvlog::Logf("server Wait() returned unexpectedly — rebuilding listener");
        continue;
    }
}
