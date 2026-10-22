#include "driver_mgr.hpp"
#include "common.h"

#include <sddl.h>

namespace suspex {

DriverMgr::SysInfo DriverMgr::Query()
{
    SysInfo info;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"SuspexDrv", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st{};
            if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING) {
                info.service = true;
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    if (drv_.Open()) {
        info.loaded = drv_.Ping(&info.ping);
    } else {
        drv_.Close();
    }
    return info;
}

std::string DriverMgr::LoadService()
{
    if (!cfg_.allowDriverLoad) {
        return "driver ops disabled by agent config";
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return Win32ErrorString("OpenSCManager", GetLastError());
    }
    std::wstring cmd = L"\\??\\" + cfg_.driverPath;
    SC_HANDLE svc = OpenServiceW(scm, L"SuspexDrv", SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        svc = CreateServiceW(scm, L"SuspexDrv", L"Suspex0 kernel driver", SERVICE_START,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            std::string err = Win32ErrorString("CreateService", GetLastError());
            CloseServiceHandle(scm);
            return err;
        }
    }
    BOOL ok = StartServiceW(svc, 0, nullptr);
    DWORD gle = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!ok && gle != ERROR_SERVICE_ALREADY_RUNNING) {
        return Win32ErrorString("StartService(SuspexDrv)", gle);
    }
    drv_.Close();
    lastError_.clear();
    return "";
}

std::string DriverMgr::UnloadService(bool delete_service)
{
    if (!cfg_.allowDriverUnload) {
        return "driver ops disabled by agent config";
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return Win32ErrorString("OpenSCManager", GetLastError());
    }
    SC_HANDLE svc = OpenServiceW(scm, L"SuspexDrv", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    CloseServiceHandle(scm);
    if (!svc) {
        return "SuspexDrv service not found";
    }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    Sleep(500);
    if (delete_service) {
        BOOL deleted = DeleteService(svc);
        DWORD gle = GetLastError();
        CloseServiceHandle(svc);
        if (!deleted && gle != ERROR_SERVICE_MARKED_FOR_DELETE) {
            // deleted only on the last handle close; a reboot clears a held driver
            return Win32ErrorString("DeleteService(SuspexDrv); reboot to complete removal", gle);
        }
    } else {
        // keep the service entry registered — the update flow replaces the
        // .sys and reloads through it; a deleted-but-lingering entry makes
        // the immediate reload fail StartService with ERROR_SERVICE_DISABLED
        CloseServiceHandle(svc);
    }
    drv_.Close();
    return "";
}

std::string DriverMgr::ManualMap(UINT32 pid)
{
    if (!cfg_.allowDriverLoad) {
        return "driver ops disabled by agent config";
    }
    Driver drv2;
    if (!drv2.Open()) {
        return "manual map requires the driver already loaded (mapper talks IOCTLs)";
    }
    if (!pid) {
        // the mapper needs a live user process hosting an alertable parked
        // thread; System (4) has no PEB->Ldr so kernelbase is not loadable
        // there — prefer explorer, fall back to our own process
        pid = GetCurrentProcessId();
        std::vector<ProcessEntry> procs;
        if (drv2.ProcessList(procs)) {
            for (auto& p : procs) {
                if (_wcsicmp(p.ImageName.c_str(), L"explorer.exe") == 0 && p.Pid != 4 &&
                    p.Pid != GetCurrentProcessId()) {
                    pid = p.Pid;
                    break;
                }
            }
        }
    }
    std::wstring params = L"--pid " + std::to_wstring(pid) + L" --image \"" + cfg_.driverPath + L"\"";
    std::wstring cmdLine = L"\"" + cfg_.mapperPath + L"\" " + params;

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readEnd = nullptr, writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) {
        return Win32ErrorString("CreatePipe", GetLastError());
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back(L'\0');
    if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        CloseHandle(readEnd);
        CloseHandle(writeEnd);
        return Win32ErrorString("CreateProcess(mapper)", GetLastError());
    }
    CloseHandle(writeEnd);
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    char buf[4096];
    DWORD read = 0;
    ReadFile(readEnd, buf, sizeof(buf) - 1, &read, nullptr);
    buf[read] = 0;
    CloseHandle(readEnd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (exitCode != 0) {
        return std::string("mapper exit=") + std::to_string(exitCode) + ": " + buf;
    }
    return "";
}

std::string RunDriverGate(DriverMgr& mgr)
{
    Driver& d = mgr.Comm();
    PingInfo p{};
    if (!d.Open() || !d.Ping(&p)) {
        return "gate: driver not reachable: " + d.LastError();
    }
    if (p.AbiVersion != SUSPEX_ABI_VERSION) {
        return "gate: driver ABI " + std::to_string(p.AbiVersion) + " != agent ABI " +
               std::to_string(SUSPEX_ABI_VERSION);
    }
    return "";
}

} // namespace suspex
