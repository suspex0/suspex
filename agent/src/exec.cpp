#include "exec.hpp"
#include "common.h"

#include <array>
#include <thread>

namespace suspex {

static std::wstring Quote(const std::wstring& s)
{
    std::wstring q = L"\"";
    q += s;
    q += L"\"";
    return q;
}

static bool Pipe(HANDLE* read, HANDLE* write)
{
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    return CreatePipe(read, write, &sa, 0) != 0;
}

static void Drain(HANDLE pipe, std::vector<BYTE>& out, HANDLE proc, DWORD timeoutMs,
                  bool* timedOut, const ExecMgr::CancelledFn& cancelled)
{
    ULONGLONG deadline = GetTickCount64() + (timeoutMs ? timeoutMs : 30000);
    CHAR buf[8192];
    DWORD n = 0;
    auto kill_child = [&]() {
        *timedOut = true;
        TerminateProcess(proc, 1);
        WaitForSingleObject(proc, 5000);
    };
    for (;;) {
        // v14: the orchestrator's wire deadline fires before our side's
        // timeout — without this the poller keeps burning until timeoutMs
        // even though the caller is gone.
        if (cancelled && cancelled()) {
            kill_child();
            break;
        }
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &n, nullptr)) {
            break;
        }
        if (n > 0) {
            if (ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n) {
                out.insert(out.end(), buf, buf + n);
            } else {
                break;
            }
        } else {
            if (WaitForSingleObject(proc, 50) == WAIT_OBJECT_0) {
                // final drain
                while (PeekNamedPipe(pipe, nullptr, 0, nullptr, &n, nullptr) && n) {
                    if (ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n) {
                        out.insert(out.end(), buf, buf + n);
                    }
                }
                break;
            }
            if (GetTickCount64() > deadline) {
                kill_child();
                break;
            }
        }
    }
}

static RunResult RunProcess(const std::wstring& cmdLine, const std::wstring& workDir,
                            DWORD timeoutMs, const ExecMgr::CancelledFn& cancelled)
{
    RunResult res;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outR = nullptr, outW = nullptr, errR = nullptr, errW = nullptr;
    if (!Pipe(&outR, &outW) || !Pipe(&errR, &errW)) {
        res.error = Win32ErrorString("CreatePipe", GetLastError());
        return res;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = outW;
    si.hStdError = errW;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd(cmdLine.begin(), cmdLine.end());
    cmd.push_back(L'\0');
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        res.error = Win32ErrorString("CreateProcess", GetLastError());
        CloseHandle(outR);
        CloseHandle(outW);
        CloseHandle(errR);
        CloseHandle(errW);
        return res;
    }
    CloseHandle(outW);
    CloseHandle(errW);
    bool timedOut = false;
    std::thread drainOut(Drain, outR, std::ref(res.out), pi.hProcess, timeoutMs,
                         &timedOut, std::cref(cancelled));
    Drain(errR, res.err, pi.hProcess, timeoutMs, &timedOut, cancelled);
    drainOut.join();
    if (timedOut) {
        res.timedOut = true;
    }
    GetExitCodeProcess(pi.hProcess, &res.exitCode);
    CloseHandle(outR);
    CloseHandle(errR);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return res;
}

RunResult ExecMgr::RunExe(const std::wstring& exe, const std::vector<std::wstring>& args,
                       const std::wstring& workDir, DWORD timeoutMs,
                       const CancelledFn& cancelled)
{
    std::wstring cmd = Quote(exe);
    for (auto& a : args) {
        cmd += L" ";
        cmd += Quote(a);
    }
    return RunProcess(cmd, workDir, timeoutMs, cancelled);
}

RunResult ExecMgr::RunShell(bool powershell, const std::string& command,
                         const std::wstring& workDir, DWORD timeoutMs,
                         const CancelledFn& cancelled)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
    std::wstring cmd(n ? n - 1 : 0, L'\0');
    if (n) {
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, cmd.data(), n);
    }
    std::wstring full;
    if (powershell) {
        // v1.0.1 Phase 2.3: force UTF-8 output encoding before the user's
        // command so stdout survives the Windows codepage ride without
        // becoming `â†’` noise. Separator is `;` so the user's command
        // text is appended verbatim.
        std::wstring body = L"[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd;
        full = L"powershell.exe -NoProfile -NonInteractive -Command " + Quote(body);
    } else {
        full = L"cmd.exe /c " + Quote(cmd);
    }
    return RunProcess(full, workDir, timeoutMs, cancelled);
}

// v1.0.1 Phase 2.3: PowerShell -EncodedCommand path.
RunResult ExecMgr::RunShellEncoded(const std::string& encoded_b64,
                                   const std::wstring& workDir,
                                   DWORD timeoutMs,
                                   const CancelledFn& cancelled)
{
    // base64 is pure ASCII, so a plain narrow→wide copy is enough.
    std::wstring w;
    w.reserve(encoded_b64.size());
    for (char c : encoded_b64) {
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    std::wstring full = L"powershell.exe -NoProfile -NonInteractive "
                        L"-OutputFormat Text -EncodedCommand " + w;
    return RunProcess(full, workDir, timeoutMs, cancelled);
}

uint32_t ExecMgr::StartShell(bool powershell, const std::wstring& workDir, std::string* err)
{
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE inR = nullptr, inW = nullptr, outR = nullptr, outW = nullptr;
    if (!Pipe(&inR, &inW) || !Pipe(&outR, &outW)) {
        *err = Win32ErrorString("CreatePipe", GetLastError());
        return 0;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = inR;
    si.hStdOutput = outW;
    si.hStdError = outW;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = powershell ? L"powershell.exe -NoProfile -NoLogo" : L"cmd.exe";
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        *err = Win32ErrorString("CreateProcess(shell)", GetLastError());
        CloseHandle(inR);
        CloseHandle(inW);
        CloseHandle(outR);
        CloseHandle(outW);
        return 0;
    }
    CloseHandle(inR);
    CloseHandle(outW);

    auto sh = std::make_shared<Shell>();
    sh->proc = pi.hProcess;
    sh->inWrite = inW;
    sh->outRead = outR;
    sh->queue = std::make_shared<EventQueue<std::vector<BYTE>>>();
    CloseHandle(pi.hThread);

    std::lock_guard<std::mutex> lk(m_);
    uint32_t id = nextShellId_++;
    shells_[id] = sh;
    std::thread(ShellReaderThread, sh, id).detach();
    return id;
}

void ShellReaderThread(std::shared_ptr<ExecMgr::Shell> shell, uint32_t id)
{
    CHAR buf[8192];
    DWORD n = 0;
    for (;;) {
        if (!PeekNamedPipe(shell->outRead, nullptr, 0, nullptr, &n, nullptr)) {
            break;
        }
        if (n == 0) {
            if (WaitForSingleObject(shell->proc, 100) == WAIT_OBJECT_0) {
                break;
            }
            continue;
        }
        if (!ReadFile(shell->outRead, buf, sizeof(buf), &n, nullptr) || !n) {
            break;
        }
        shell->queue->Push(std::vector<BYTE>(buf, buf + n));
    }
    shell->queue->Push({}); // eof marker
}

bool ExecMgr::WriteShell(uint32_t id, const std::string& data, std::string* err)
{
    std::shared_ptr<Shell> sh;
    {
        std::lock_guard<std::mutex> lk(m_);
        auto it = shells_.find(id);
        if (it == shells_.end()) {
            *err = "no such shell session";
            return false;
        }
        sh = it->second;
    }
    DWORD w = 0;
    if (!WriteFile(sh->inWrite, data.data(), (DWORD)data.size(), &w, nullptr)) {
        *err = Win32ErrorString("WriteFile(shell)", GetLastError());
        return false;
    }
    return true;
}

bool ExecMgr::StopShell(uint32_t id, std::string* err)
{
    std::shared_ptr<Shell> sh;
    {
        std::lock_guard<std::mutex> lk(m_);
        auto it = shells_.find(id);
        if (it == shells_.end()) {
            *err = "no such shell session";
            return false;
        }
        sh = it->second;
        shells_.erase(it);
    }
    // handles close when the last shared_ptr (ours + reader thread) drops;
    // terminating first makes the reader thread exit its pipe loop
    TerminateProcess(sh->proc, 1);
    return true;
}

std::shared_ptr<ExecMgr::Shell> ExecMgr::GetShell(uint32_t id)
{
    std::lock_guard<std::mutex> lk(m_);
    auto it = shells_.find(id);
    return it == shells_.end() ? nullptr : it->second;
}

std::vector<uint32_t> ExecMgr::ShellIds()
{
    std::vector<uint32_t> ids;
    std::lock_guard<std::mutex> lk(m_);
    ids.reserve(shells_.size());
    for (auto& kv : shells_) {
        ids.push_back(kv.first);
    }
    return ids;
}

// ---- process suspend/resume (NtSuspendProcess / NtResumeProcess) ----

using NtSuspendResumeFn = LONG(WINAPI*)(HANDLE);

std::string ExecMgr::Suspend(uint32_t pid)
{
    if (pid == GetCurrentProcessId()) {
        return "refusing to suspend the agent itself";
    }
    static NtSuspendResumeFn ntSuspend = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtSuspendResumeFn)GetProcAddress(ntdll, "NtSuspendProcess") : nullptr;
    }();
    if (!ntSuspend) {
        return "NtSuspendProcess unavailable";
    }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        return Win32ErrorString("OpenProcess(PROCESS_SUSPEND_RESUME)", GetLastError());
    }
    LONG st = ntSuspend(h);
    CloseHandle(h);
    return st == 0 ? "" : ("NtSuspendProcess failed nt=0x" + std::to_string((UINT32)st));
}

std::string ExecMgr::Resume(uint32_t pid)
{
    if (pid == GetCurrentProcessId()) {
        return "refusing to resume the agent itself (it is not suspended)";
    }
    static NtSuspendResumeFn ntResume = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtSuspendResumeFn)GetProcAddress(ntdll, "NtResumeProcess") : nullptr;
    }();
    if (!ntResume) {
        return "NtResumeProcess unavailable";
    }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        return Win32ErrorString("OpenProcess(PROCESS_SUSPEND_RESUME)", GetLastError());
    }
    LONG st = ntResume(h);
    CloseHandle(h);
    return st == 0 ? "" : ("NtResumeProcess failed nt=0x" + std::to_string((UINT32)st));
}

} // namespace suspex
