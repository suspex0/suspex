#pragma once

// v7: first-class detached execution surface for the "run + poll" pattern
// the developer feedback (2026-09-09) documented. `run_exe` blocks the
// agent worker until the child exits — when a child hangs the target the
// RPC dies with DEADLINE_EXCEEDED and stdout is lost. `RunDetached`
// spawns with CREATE_NEW_PROCESS_GROUP, redirects stdout/stderr to
// per-handle log files, and returns immediately with an opaque handle;
// callers poll status / tail the logs / kill the tree without ever
// holding a live gRPC call open across the child's lifetime.

#include <windows.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace suspex {

struct DetachedHandle {
    std::string id;             // 24-char hex id
    DWORD pid = 0;
    HANDLE process = nullptr;   // owned; closed on erase
    HANDLE thread = nullptr;    // owned; closed on erase
    std::wstring stdout_path;
    std::wstring stderr_path;
    uint64_t started_ts = 0;
    uint64_t exited_ts = 0;
    DWORD exit_code = 0;
    std::atomic<bool> running{true};

    ~DetachedHandle()
    {
        if (thread) CloseHandle(thread);
        if (process) CloseHandle(process);
    }
};

class DetachedRegistry {
public:
    // Spawn and register. `stdout_path` / `stderr_path` may be empty
    // (agent chooses under %ProgramData%\suspex\detached\<id>). Returns
    // the handle on success; `err` populated on failure.
    std::shared_ptr<DetachedHandle> Spawn(const std::wstring& cmdline,
                                          const std::wstring& workdir,
                                          const std::wstring& stdout_path,
                                          const std::wstring& stderr_path,
                                          bool hidden_window,
                                          std::string* err);

    std::shared_ptr<DetachedHandle> Get(const std::string& id);
    bool Kill(const std::string& id, std::string* err);
    // Called from the poll path: if the process has actually exited, stamp
    // exit_code / exited_ts and mark running=false. Returns after any
    // needed cleanup — the handle stays in the registry until the caller
    // asks for its status one last time (so `running=false` is observable
    // exactly once per lifetime without racing the reaper).
    void Poll(const std::shared_ptr<DetachedHandle>& h);

private:
    std::mutex m_;
    std::unordered_map<std::string, std::shared_ptr<DetachedHandle>> map_;
};

} // namespace suspex
