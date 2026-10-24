#include "srv_log.hpp"

#include <windows.h>

#include <fcntl.h>
#include <io.h>
#include <process.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

namespace suspex::srvlog {

namespace {

struct LogState {
    std::mutex m;
    HANDLE file = nullptr; // FILE_APPEND_DATA handle, or null when closed
    std::wstring path;
    size_t cap = 4 * 1024 * 1024;
    int open_misses = 0; // failed (re)opens since the last success
    uint64_t last_retry_ms = 0;
};

uint64_t NowMs()
{
    return (uint64_t)GetTickCount64();
}

LogState& State()
{
    static LogState s;
    return s;
}

HANDLE ReopenLocked(LogState& s)
{
    // FILE_SHARE_READ|FILE_SHARE_WRITE: benign multi-process append (the
    // rig runs one agent per log, but a retrying second instance or a
    // --dev side run must not lose its log entirely). Append-mode writes
    // are positioned atomically per WriteFile.
    s.file = CreateFileW(s.path.c_str(), FILE_APPEND_DATA | GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (s.file == INVALID_HANDLE_VALUE) {
        s.file = nullptr;
    }
    return s.file;
}

// Caller holds State().m.
void WriteLineLocked(LogState& s, const char* line)
{
    if (!s.file) return;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(s.file, &sz) && (size_t)sz.QuadPart > s.cap) {
        CloseHandle(s.file);
        s.file = nullptr;
        std::wstring old = s.path + L".1";
        MoveFileExW(s.path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING);
        if (!ReopenLocked(s)) return;
    }
    DWORD written = 0;
    WriteFile(s.file, line, (DWORD)strlen(line), &written, nullptr);
}

// stderr relay: reads the pipe that now backs stderr and appends each
// complete line to the rotating log. Detached — runs for process
// lifetime. Bounded pending buffer so a pathological no-newline writer
// cannot grow memory without limit.
void RelayThread(HANDLE readEnd)
{
    std::string pending;
    pending.reserve(512);
    char buf[4096];
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(readEnd, buf, sizeof(buf), &n, nullptr) || n == 0) {
            if (pending.empty()) break; // write end closed and drained
            Logf("stderr %s", pending.c_str());
            pending.clear();
            break;
        }
        pending.append(buf, n);
        for (;;) {
            size_t nl = pending.find('\n');
            if (nl == std::string::npos) break;
            size_t end = nl;
            if (end > 0 && pending[end - 1] == '\r') end--;
            Logf("stderr %.*s", (int)end, pending.c_str());
            pending.erase(0, nl + 1);
        }
        if (pending.size() > 8192) { // no-newline firehose guard
            Logf("stderr %s", pending.c_str());
            pending.clear();
        }
    }
}

} // namespace

void Open(const std::wstring& path, std::size_t max_bytes)
{
    LogState& s = State();
    if (path.empty()) return;
    std::lock_guard<std::mutex> lk(s.m);
    if (s.file) {
        CloseHandle(s.file);
        s.file = nullptr;
    }
    s.path = path;
    if (max_bytes) s.cap = max_bytes;
    ReopenLocked(s);
    if (s.file) s.open_misses = 0;
}

void Close()
{
    LogState& s = State();
    std::lock_guard<std::mutex> lk(s.m);
    if (s.file) {
        CloseHandle(s.file);
        s.file = nullptr;
    }
}

bool Enabled()
{
    LogState& s = State();
    std::lock_guard<std::mutex> lk(s.m);
    return s.file != nullptr;
}

void Logf(const char* fmt, ...)
{
    LogState& s = State();
    char stamp[40];
    SYSTEMTIME st{};
    GetSystemTime(&st);
    _snprintf_s(stamp, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                st.wSecond, st.wMilliseconds);
    char body[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(body, _TRUNCATE, fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(s.m);
    // Lazy re-open: a transient lock (e.g. a concurrent reader holding the
    // file while the previous process died) must not silence the agent for
    // its whole lifetime — retry every 10s and say so once we're back.
    if (!s.file && !s.path.empty() && NowMs() - s.last_retry_ms >= 10000) {
        s.last_retry_ms = NowMs();
        ReopenLocked(s);
        if (s.file) {
            int misses = s.open_misses;
            s.open_misses = 0;
            if (misses > 0) {
                char note[96];
                _snprintf_s(note, _TRUNCATE,
                            "(log reopened after %d failed open attempts)", misses);
                WriteLineLocked(s, stamp);
                WriteLineLocked(s, note);
                WriteLineLocked(s, "\n");
            }
        } else {
            s.open_misses++;
        }
    }
    if (!s.file) {
        s.open_misses++;
        return;
    }
    WriteLineLocked(s, stamp);
    WriteLineLocked(s, body);
    WriteLineLocked(s, "\n");
}

void CaptureStderr()
{
    LogState& s = State();
    if (!s.file) return; // no log open: nothing to relay into

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    HANDLE readEnd = nullptr, writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) {
        return;
    }

    // stdout has nothing worth keeping — kill it first.
    FILE* f = nullptr;
    freopen_s(&f, "NUL", "w", stdout);

    // Splice the pipe under stderr at BOTH levels: the OS handle (native
    // WriteFile(GetStdHandle(STD_ERROR_HANDLE)) writers, e.g. absl
    // logging) and CRT fd 2 (fprintf(stderr) writers). The relay thread
    // drains the pipe so neither can ever block on a full buffer.
    SetStdHandle(STD_ERROR_HANDLE, writeEnd);
    int fd = _open_osfhandle((intptr_t)writeEnd, _O_WRONLY | _O_TEXT);
    if (fd != -1) {
        _dup2(fd, 2);
        // fd was consumed by _dup2's duplication; close the original.
        _close(fd);
    }
    std::thread(RelayThread, readEnd).detach();
}

void RedirectStdioToNul()
{
    FILE* f = nullptr;
    freopen_s(&f, "NUL", "w", stdout);
    freopen_s(&f, "NUL", "w", stderr);
}

} // namespace suspex::srvlog
