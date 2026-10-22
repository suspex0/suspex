// Session-0 dispatcher: relaunches the agent binary inside the active console
// session (CreateProcessAsUserW + --screenshot) and reads the IPC packet back
// over an anonymous pipe.
//
// NOTE: window enumeration / capture MUST run in the session-1 worker — a
// Session-0 service cannot see user-desktop windows via EnumWindows.
#include "screen_common.hpp"

#include <wtsapi32.h>

#include <algorithm>
#include <chrono>
#include <vector>

#include "suspex.grpc.pb.h"

namespace suspex {
namespace screen {

// v1: v0-sketch blocked in ReadFile forever if the child hung. Anonymous
// pipes support PeekNamedPipe — poll availability with a hard deadline.
static bool ReadExact(HANDLE hPipe, void* dst, DWORD len, DWORD timeoutMs)
{
    DWORD total = 0;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (total < len) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hPipe, nullptr, 0, nullptr, &avail, nullptr)) {
            return false;   // child died / pipe broke
        }
        if (avail == 0) {
            if (GetTickCount64() >= deadline) {
                return false;
            }
            Sleep(15);
            continue;
        }
        DWORD read = 0;
        if (!ReadFile(hPipe, (BYTE*)dst + total,
                      (std::min)(avail, len - total),
                      &read, nullptr) || read == 0) {
            return false;
        }
        total += read;
    }
    return true;
}

static void Fail(ScreenCaptureResponse* resp, const char* err)
{
    resp->mutable_status()->set_ok(false);
    resp->mutable_status()->set_error(err);
}

bool DispatchScreenCapture(const ScreenCaptureRequest& req, ScreenCaptureResponse* resp)
{
    const DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        Fail(resp, "no_active_console_session");
        return false;
    }

    HANDLE hUserToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &hUserToken)) {
        Fail(resp, "WTSQueryUserToken failed: machine locked or logged off");
        return false;
    }

    HANDLE hPrimaryToken = nullptr;
    if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, nullptr,
                          SecurityIdentification, TokenPrimary, &hPrimaryToken)) {
        CloseHandle(hUserToken);
        Fail(resp, "DuplicateTokenEx failed");
        return false;
    }
    CloseHandle(hUserToken);

    HANDLE hRead = nullptr, hWrite = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        CloseHandle(hPrimaryToken);
        Fail(resp, "CreatePipe failed");
        return false;
    }

    wchar_t selfPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    std::wstring cmd = L"\"" + std::wstring(selfPath) + L"\" --screenshot --pipe "
                     + std::to_wstring((uintptr_t)hWrite)
                     + L" --mode " + std::wstring(req.mode().begin(), req.mode().end());

    if (!req.display_id().empty()) {
        cmd += L" --display " + std::wstring(req.display_id().begin(),
                                             req.display_id().end());
    }
    if (req.hwnd() != 0) {
        cmd += L" --hwnd " + std::to_wstring(req.hwnd());
    }
    if (req.pid() != 0) {
        cmd += L" --pid " + std::to_wstring(req.pid());
    }
    // Filters travel hex-encoded so arbitrary text survives the command line.
    if (!req.window_title().empty()) {
        const std::string hx = WsToHexArg(std::wstring(req.window_title().begin(),
                                                       req.window_title().end()));
        cmd += L" --title-hex " + std::wstring(hx.begin(), hx.end());
    }
    if (!req.process_name().empty()) {
        const std::string hx = WsToHexArg(std::wstring(req.process_name().begin(),
                                                       req.process_name().end()));
        cmd += L" --proc-hex " + std::wstring(hx.begin(), hx.end());
    }
    if (!req.query().empty()) {
        const std::string hx = WsToHexArg(std::wstring(req.query().begin(),
                                                       req.query().end()));
        cmd += L" --query-hex " + std::wstring(hx.begin(), hx.end());
    }
    if (req.include_hidden()) {
        cmd += L" --include-hidden";
    }
    if (!req.include_details()) {
        cmd += L" --no-details";
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};
    const BOOL spawned = CreateProcessAsUserW(
        hPrimaryToken, nullptr, cmd.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    // Critical: the parent must close its write end so the pipe signals EOF.
    CloseHandle(hWrite);
    CloseHandle(hPrimaryToken);

    auto reap = [&pi]() {
        if (pi.hProcess) {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    };

    if (!spawned) {
        CloseHandle(hRead);
        Fail(resp, "CreateProcessAsUserW failed");
        return false;
    }

    ScreenIpcHeader hdr{};
    if (!ReadExact(hRead, &hdr, sizeof(hdr), 5000) ||
        hdr.magic != SCREEN_IPC_MAGIC || hdr.status != 0) {
        CloseHandle(hRead);
        reap();
        Fail(resp, "screen_worker failed or timed out");
        return false;
    }

    std::vector<uint8_t> pngBytes(hdr.png_len);
    if (hdr.png_len > 0 && !ReadExact(hRead, pngBytes.data(), hdr.png_len, 10000)) {
        CloseHandle(hRead);
        reap();
        Fail(resp, "screen_worker: truncated png payload");
        return false;
    }
    std::string jsonMeta(hdr.json_len, '\0');
    if (hdr.json_len > 0 && !ReadExact(hRead, jsonMeta.data(), hdr.json_len, 10000)) {
        CloseHandle(hRead);
        reap();
        Fail(resp, "screen_worker: truncated json payload");
        return false;
    }

    CloseHandle(hRead);
    reap();

    resp->mutable_status()->set_ok(true);
    resp->set_image_data(pngBytes.data(), pngBytes.size());
    resp->set_width(hdr.width);
    resp->set_height(hdr.height);
    const auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    resp->set_timestamp_unix_ms(now_ms);
    resp->set_windows_json(jsonMeta);   // delivered even for plain captures
    return true;
}

} // namespace screen
} // namespace suspex
