#include "service_main.hpp"

#include <windows.h>

#include <thread>

namespace suspex {

static SERVICE_STATUS g_status;
static SERVICE_STATUS_HANDLE g_handle;
static int (*g_fn)(int, char**) = nullptr;
static int g_argc = 0;
static char** g_argv = nullptr;
static std::thread g_worker;

static void SetState(DWORD state, DWORD exit = 0, DWORD waitHint = 0)
{
    if (!g_handle) {
        return;
    }
    static DWORD checkpoint = 0;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exit;
    g_status.dwCheckPoint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : ++checkpoint;
    g_status.dwWaitHint = waitHint;
    SetServiceStatus(g_handle, &g_status);
}

// v1 stop handling is coarse: SCM STOP reports STOPPED and exits the process
// (the gRPC server has no async shutdown hook wired here yet). Lab-acceptable:
// redeploy flows reboot or re-run the installer anyway.
static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetState(SERVICE_STOP_PENDING, 0, 5000);
        SetState(SERVICE_STOPPED);
        ExitProcess(0);
        return NO_ERROR;
    default:
        return NO_ERROR;
    }
}

static VOID WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_handle = RegisterServiceCtrlHandlerExW(L"SuspexAgent", ServiceCtrlHandler, nullptr);
    if (!g_handle) {
        // never fall back to console mode when launched by SCM: a silent
        // console run makes SCM time out and kill the process (7009/7034)
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetState(SERVICE_START_PENDING, 0, 5000);
    g_worker = std::thread([] {
        SetState(SERVICE_RUNNING);
        g_fn(g_argc, g_argv);
        SetState(SERVICE_STOPPED);
    });
    // SCM blocks here until the process exits
    g_worker.join();
}

int RunAsServiceOrConsole(bool console, const std::string& serviceName,
                          int (*fn)(int, char**), int argc, char** argv)
{
    if (console) {
        return fn(argc, argv);
    }
    wchar_t wname[128];
    MultiByteToWideChar(CP_UTF8, 0, serviceName.c_str(), -1, wname, 128);
    SERVICE_TABLE_ENTRYW table[2]{};
    table[0].lpServiceName = wname;
    table[0].lpServiceProc = ServiceMain;
    g_fn = fn;
    g_argc = argc;
    g_argv = argv;
    if (!StartServiceCtrlDispatcherW(table)) {
        // genuinely not started by SCM (double-click etc.): console fallback.
        // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT is the expected marker.
        if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return 1;
        }
        return fn(argc, argv);
    }
    return 0;
}

} // namespace suspex
