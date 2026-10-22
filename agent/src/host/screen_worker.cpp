// The --screenshot child: re-launch of suspex_agent.exe inside the active
// console session (the Session-0 service cannot see the user desktop).
// Parses the CLI, runs the requested capture/enumeration, and ships one
// ScreenIpcHeader + payload down the inherited pipe.
#include "screen_common.hpp"

#include <dwmapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace suspex {
namespace screen {

bool CaptureDesktopDxgi(const std::string& displayArg, std::vector<uint8_t>& outPng,
                        uint32_t& outW, uint32_t& outH);
bool CaptureWindowWgc(HWND hwnd, std::vector<uint8_t>& outPng,
                      uint32_t& outW, uint32_t& outH);
bool CaptureDisplaysJson(std::string& outJson);
std::string EnumerateWindowsJson(DWORD filterPid, const std::wstring& filterName,
                                 const std::wstring& query,
                                 bool includeHidden, bool includeDetails);

namespace {

// Resolve a capture target when only a filter was given.
// Precedence: exact pid > title substring > process image name; picks the
// topmost visible, non-cloaked, non-zero-size match (EnumWindows order).
struct ResolveCtx {
    const wchar_t* title = nullptr;   // substring or nullptr
    const wchar_t* proc = nullptr;    // substring or nullptr
    DWORD pid = 0;
    HWND found = nullptr;
};

BOOL CALLBACK ResolveWndProc(HWND hwnd, LPARAM lp)
{
    auto* r = reinterpret_cast<ResolveCtx*>(lp);
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }
    int cloaked = 0;
    DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked));
    if (cloaked) {
        return TRUE;
    }
    RECT rc{};
    if (!GetWindowRect(hwnd, &rc) || rc.right <= rc.left || rc.bottom <= rc.top) {
        return TRUE;
    }
    if (r->pid) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != r->pid) {
            return TRUE;
        }
        r->found = hwnd;
        return FALSE;
    }
    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, 512);
    if (r->title && !wcsstr(title, r->title)) {
        return TRUE;
    }
    if (r->proc) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        std::wstring name, full;
        if (!QueryProcessImage(pid, name, full)) {
            return TRUE;
        }
        if (name.find(r->proc) == std::wstring::npos &&
            full.find(r->proc) == std::wstring::npos) {
            return TRUE;
        }
    }
    if (!r->title && !r->proc) {
        return TRUE;
    }
    r->found = hwnd;
    return FALSE;
}

} // namespace

int RunScreenWorkerCli(int argc, char** argv)
{
    // Opt into per-monitor-v2 so GetDpiForWindow reports real DPIs instead of
    // virtualized system DPI.
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    HANDLE hPipe = nullptr;
    std::string mode = "desktop";
    std::string displayArg;     // index ("1") or device name ("DISPLAY1"); "" = primary
    HWND targetHwnd = nullptr;
    DWORD targetPid = 0;
    std::wstring titleSubstr, procSubstr, query;
    bool includeHidden = false; // default = visible windows only
    bool includeDetails = true; // default = full metadata block

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--pipe") && i + 1 < argc) {
            hPipe = (HANDLE)(uintptr_t)_strtoui64(argv[++i], nullptr, 10);
        } else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            mode = argv[++i];
        } else if (!strcmp(argv[i], "--hwnd") && i + 1 < argc) {
            targetHwnd = (HWND)(uintptr_t)_strtoui64(argv[++i], nullptr, 0);
        } else if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            targetPid = (DWORD)strtoul(argv[++i], nullptr, 10);
        } else if (!strcmp(argv[i], "--display") && i + 1 < argc) {
            displayArg = argv[++i];
        } else if (!strcmp(argv[i], "--title-hex") && i + 1 < argc) {
            titleSubstr = HexArgToWs(argv[++i]);
        } else if (!strcmp(argv[i], "--proc-hex") && i + 1 < argc) {
            procSubstr = HexArgToWs(argv[++i]);
        } else if (!strcmp(argv[i], "--query-hex") && i + 1 < argc) {
            query = HexArgToWs(argv[++i]);
        } else if (!strcmp(argv[i], "--include-hidden")) {
            includeHidden = true;
        } else if (!strcmp(argv[i], "--no-details")) {
            includeDetails = false;
        }
    }

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE) {
        hPipe = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    // Resolve the window target by pid > title > process name.
    if (mode == "window" && !targetHwnd) {
        ResolveCtx r;
        r.title = titleSubstr.empty() ? nullptr : titleSubstr.c_str();
        r.proc = procSubstr.empty() ? nullptr : procSubstr.c_str();
        r.pid = targetPid;
        EnumWindows(ResolveWndProc, (LPARAM)&r);
        targetHwnd = r.found;
    }

    std::vector<uint8_t> pngBytes;
    std::string jsonMeta;
    uint32_t w = 0, h = 0;
    bool ok = false;

    if (mode == "window") {
        if (targetHwnd) {
            ok = CaptureWindowWgc(targetHwnd, pngBytes, w, h);
        }
    } else if (mode == "list") {
        ok = true;   // window listing only
    } else if (mode == "displays") {
        ok = CaptureDisplaysJson(jsonMeta);   // no pixels, topology JSON
    } else {
        ok = CaptureDesktopDxgi(displayArg, pngBytes, w, h);
    }

    if (mode != "displays") {
        jsonMeta = EnumerateWindowsJson(mode == "window" ? targetPid : 0,
                                        procSubstr, query,
                                        includeHidden, includeDetails);
    }

    ScreenIpcHeader hdr{};
    hdr.magic = SCREEN_IPC_MAGIC;
    hdr.status = ok ? 0 : 1;
    hdr.width = w;
    hdr.height = h;
    hdr.png_len = (uint32_t)pngBytes.size();
    hdr.json_len = (uint32_t)jsonMeta.size();

    DWORD written = 0;
    WriteFile(hPipe, &hdr, sizeof(hdr), &written, nullptr);
    if (hdr.png_len > 0 && !pngBytes.empty()) {
        WriteFile(hPipe, pngBytes.data(), hdr.png_len, &written, nullptr);
    }
    if (hdr.json_len > 0 && !jsonMeta.empty()) {
        WriteFile(hPipe, jsonMeta.data(), hdr.json_len, &written, nullptr);
    }
    FlushFileBuffers(hPipe);
    return ok ? 0 : 1;
}

} // namespace screen
} // namespace suspex
