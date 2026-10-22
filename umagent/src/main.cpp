#include "um_services.hpp"
#include "umem.hpp"

#include <grpcpp/grpcpp.h>

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
            "       [--max-read-mb 8] [--dev]\n");
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

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_handle = RegisterServiceCtrlHandlerExW(L"SuspexUmagent", ServiceCtrlHandler, nullptr);
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
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            cfg.port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--token") && i + 1 < argc) {
            cfg.token = argv[++i];
        } else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
            cfg.bind = argv[++i];
        } else if (!strcmp(argv[i], "--max-read-mb") && i + 1 < argc) {
            cfg.maxReadBytes = (uint64_t)atoi(argv[++i]) << 20;
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

    std::string addr = cfg.bind + ":" + std::to_string(cfg.port);
    grpc::ServerBuilder builder;
    builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
    // Same fix as the agent: stock sync-server defaults starve the view
    // after two concurrent blocking calls.
    builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
    builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
    um::RegisterServices(builder, cfg);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    if (!server) {
        fprintf(stderr, "failed to listen on %s\n", addr.c_str());
        return 1;
    }
    printf("suspex_umagent %s listening on %s (auth %s)\n", cfg.version.c_str(), addr.c_str(),
           cfg.token.empty() ? "DISABLED" : "token");
    fflush(stdout);
    server->Wait();
    return 0;
}
