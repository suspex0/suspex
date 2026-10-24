#include "service_main.hpp"

#include <windows.h>

#include <functional>
#include <mutex>
#include <thread>

namespace suspex {

static SERVICE_STATUS g_status;
static SERVICE_STATUS_HANDLE g_handle;
static int (*g_fn)(int, char**) = nullptr;
static int g_argc = 0;
static char** g_argv = nullptr;
static std::thread g_worker;
static HANDLE g_worker_done = nullptr; // set when g_fn returned
static std::mutex g_hook_m;
static std::function<void()> g_stop_hook;

void SetServiceStopHook(std::function<void()> hook)
{
    std::lock_guard<std::mutex> lk(g_hook_m);
    g_stop_hook = std::move(hook);
}

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

// v1.0.1 Phase 5: STOP now asks the agent to unwind first (SetServiceStopHook
// — the gRPC server shuts down, breadcrumbs flush, worker reports STOPPED).
// ExitProcess stays as a bounded backstop so SCM never hangs on a wedged
// stop path.
static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN: {
        SetState(SERVICE_STOP_PENDING, 0, 15000);
        std::function<void()> hook;
        {
            std::lock_guard<std::mutex> lk(g_hook_m);
            hook = g_stop_hook;
        }
        if (hook) {
            hook();
        }
        if (g_worker_done) {
            WaitForSingleObject(g_worker_done, 12000);
        }
        ExitProcess(0);
        return NO_ERROR;
    }
    default:
        return NO_ERROR;
    }
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    // Register under the name SCM actually used (argv[0]); the hardcoded
    // fallback only covers exotic dispatch paths. A mismatched name made
    // RegisterServiceCtrlHandlerExW fail and the service die silently.
    LPCWSTR name = (argc > 0 && argv && argv[0]) ? argv[0] : L"SuspexAgent";
    g_handle = RegisterServiceCtrlHandlerExW(name, ServiceCtrlHandler, nullptr);
    if (!g_handle) {
        // never fall back to console mode when launched by SCM: a silent
        // console run makes SCM time out and kill the process (7009/7034)
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetState(SERVICE_START_PENDING, 0, 5000);
    g_worker_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_worker = std::thread([] {
        SetState(SERVICE_RUNNING);
        g_fn(g_argc, g_argv);
        SetState(SERVICE_STOPPED);
        if (g_worker_done) {
            SetEvent(g_worker_done);
        }
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
