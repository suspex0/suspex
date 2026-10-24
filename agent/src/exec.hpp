#pragma once

#include <windows.h>

#include "src/events.hpp"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace suspex {

struct RunResult {
    std::string error;
    DWORD exitCode = 0;
    std::vector<BYTE> out;
    std::vector<BYTE> err;
    bool timedOut = false;
};

class ExecMgr {
public:
    // `cancelled` — when set and it reports true, the child is terminated
    // early and the call returns (gRPC client-side deadline already fired;
    // burning a poller for the rest of timeoutMs is how the exec queue
    // used to wedge indefinitely).
    using CancelledFn = std::function<bool()>;
    RunResult RunExe(const std::wstring& exe, const std::vector<std::wstring>& args,
                     const std::wstring& workDir, DWORD timeoutMs,
                     const CancelledFn& cancelled = {});
    RunResult RunShell(bool powershell, const std::string& command,
                       const std::wstring& workDir, DWORD timeoutMs,
                       const CancelledFn& cancelled = {});
    // v0.31 Phase 2.3: quoting-proof PowerShell spawn. `encoded_b64` is a
    // base64-encoded UTF-16LE command string that goes straight to
    // ``powershell -EncodedCommand <b64>`` — immune to the double-parse
    // mangling that bites ``-Command <quoted>`` on embedded quotes,
    // backticks, newlines, and non-ASCII. Only valid for PowerShell.
    RunResult RunShellEncoded(const std::string& encoded_b64,
                              const std::wstring& workDir, DWORD timeoutMs,
                              const CancelledFn& cancelled = {});

    // persistent shell sessions; shared_ptr-owned so a reader thread and an
    // RPC handler can hold one safely while StopShell unmaps the id
    struct Shell {
        HANDLE proc = nullptr;
        HANDLE inWrite = nullptr;
        HANDLE outRead = nullptr;
        std::shared_ptr<EventQueue<std::vector<BYTE>>> queue;
        ~Shell()
        {
            if (proc) {
                CloseHandle(proc);
            }
            if (inWrite) {
                CloseHandle(inWrite);
            }
            if (outRead) {
                CloseHandle(outRead);
            }
        }
    };

    uint32_t StartShell(bool powershell, const std::wstring& workDir, std::string* err);
    bool WriteShell(uint32_t id, const std::string& data, std::string* err);
    bool StopShell(uint32_t id, std::string* err);
    std::shared_ptr<Shell> GetShell(uint32_t id);
    // v14: live session ids for Exec.ListShells — recovery path when a
    // caller's session_id was stripped in transit.
    std::vector<uint32_t> ShellIds();

    // target quiescence (NtSuspendProcess/NtResumeProcess via ntdll)
    std::string Suspend(uint32_t pid);
    std::string Resume(uint32_t pid);

private:
    std::map<uint32_t, std::shared_ptr<Shell>> shells_;
    uint32_t nextShellId_ = 1;
    std::mutex m_;
};

// reader thread body pumping a persistent shell's stdout into its queue
void ShellReaderThread(std::shared_ptr<ExecMgr::Shell> shell, uint32_t id);

} // namespace suspex
