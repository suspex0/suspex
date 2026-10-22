// Window enumeration with full per-window metadata, grouped by process.
//
// Runs ONLY in the session-1 worker (--screenshot child): a Session-0 service
// enumerates its own (non-interactive) window station and cannot see user
// desktop windows.
//
// All per-window getters (GetWindowTextW, GetClassNameW, GetWindowInfo,
// GetWindowPlacement, GetWindowLongPtrW, GetDpiForWindow) are message-free
// against other-process windows (kernel-side caption cache / non-sending
// getters), so enumerating hidden windows cannot hang on a wedged app. Do NOT
// swap GetWindowTextW for SendMessageTimeout(WM_GETTEXT) — that WOULD hang.
#include "screen_common.hpp"

#include <dwmapi.h>
#include <psapi.h>

#include <algorithm>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace suspex {
namespace screen {

struct RawWindowEntry {
    HWND hwnd = nullptr;
    DWORD pid = 0, tid = 0;
    std::wstring process_name, process_path, title, cls;
    RECT rcWindow{}, rcClient{}, rcNormal{};
    DWORD style = 0, exstyle = 0, winStatus = 0, borderCX = 0, borderCY = 0;
    DWORD showCmd = 0, atomType = 0, dpi = 0;
    ULONG_PTR hinstance = 0;
    HWND parent = nullptr, owner = nullptr;
    bool fg = false, iconic = false, zoomed = false, visible = false;
    bool enabled = false, cloaked = false;
    int z_order = 0;   // EnumWindows order, 0 = top-most
};

struct EnumCtx {
    std::vector<RawWindowEntry> list;   // insertion order = Z order
    bool include_hidden = false;        // false = visible-only behavior
    bool include_details = true;        // full metadata block
    HWND fgHwnd = nullptr;              // cached once per enum
};

static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    auto* c = reinterpret_cast<EnumCtx*>(lParam);

    const bool visible = IsWindowVisible(hwnd) != 0;
    if (!visible && !c->include_hidden) {
        return TRUE;    // default: visible only
    }

    int cloaked = 0;
    DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked));
    if (cloaked != 0 && !c->include_hidden) {
        return TRUE;    // UWP suspended / explorer-hosted previews
    }

    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) {
        return TRUE;
    }
    if (!c->include_hidden &&
        ((rc.right - rc.left) <= 0 || (rc.bottom - rc.top) <= 0)) {
        return TRUE;
    }

    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, 512);
    if (!c->include_hidden && title[0] == L'\0') {
        return TRUE;    // keeps the visible-mode untitled filter
    }

    RawWindowEntry e;
    e.hwnd = hwnd;
    e.visible = visible;
    e.cloaked = cloaked != 0;
    e.title = title;
    e.rcWindow = rc;
    e.fg = (hwnd == c->fgHwnd);
    e.iconic = IsIconic(hwnd) != 0;
    e.zoomed = IsZoomed(hwnd) != 0;
    e.enabled = IsWindowEnabled(hwnd) != 0;
    e.z_order = (int)c->list.size();    // EnumWindows is top-to-bottom Z order
    e.tid = GetWindowThreadProcessId(hwnd, &e.pid);
    QueryProcessImage(e.pid, e.process_name, e.process_path);

    if (c->include_details) {
        WINDOWINFO wi{ sizeof(wi) };
        if (GetWindowInfo(hwnd, &wi)) {
            e.style = wi.dwStyle;
            e.exstyle = wi.dwExStyle;
            e.winStatus = wi.dwWindowStatus;
            e.rcClient = wi.rcClient;
            e.borderCX = wi.cxWindowBorders;
            e.borderCY = wi.cyWindowBorders;
            e.atomType = wi.atomWindowType;
        }
        WINDOWPLACEMENT wp{ sizeof(wp) };
        if (GetWindowPlacement(hwnd, &wp)) {
            e.showCmd = wp.showCmd;
            e.rcNormal = wp.rcNormalPosition;
        }
        wchar_t cls[256]{};
        GetClassNameW(hwnd, cls, 256);
        e.cls = cls;
        e.owner = GetWindow(hwnd, GW_OWNER);
        // WINDOWINFO carries no parent; GA_PARENT is the nearest ancestor.
        e.parent = GetAncestor(hwnd, GA_PARENT);
        e.hinstance = (ULONG_PTR)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
        // Real DPI only because the worker opted into per-monitor-v2 first.
        e.dpi = GetDpiForWindow(hwnd);
    }

    c->list.push_back(std::move(e));
    return TRUE;
}

std::string EnumerateWindowsJson(DWORD filterPid, const std::wstring& filterName,
                                 const std::wstring& query,
                                 bool includeHidden, bool includeDetails)
{
    EnumCtx c;
    c.include_hidden = includeHidden;
    c.include_details = includeDetails;
    c.fgHwnd = GetForegroundWindow();
    EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&c));

    // Group by pid; pidOrder keeps first-seen (top-most z) order so output is
    // deterministic across calls (unordered_map iteration is not).
    std::unordered_map<DWORD, std::vector<const RawWindowEntry*>> groups;
    std::vector<DWORD> pidOrder;
    for (const auto& w : c.list) {
        if (filterPid != 0 && w.pid != filterPid) {
            continue;
        }
        if (!filterName.empty() &&
            w.process_name.find(filterName) == std::wstring::npos &&
            w.process_path.find(filterName) == std::wstring::npos) {
            continue;
        }
        if (!query.empty() &&
            w.title.find(query) == std::wstring::npos &&
            w.cls.find(query) == std::wstring::npos) {
            continue;
        }
        if (groups.find(w.pid) == groups.end()) {
            pidOrder.push_back(w.pid);
        }
        groups[w.pid].push_back(&w);
    }

    std::ostringstream ss;
    ss << "{\"include_hidden\":" << (includeHidden ? "true" : "false")
       << ",\"include_details\":" << (includeDetails ? "true" : "false")
       << ",\"processes\":[";
    bool firstProc = true;
    for (DWORD pid : pidOrder) {
        if (!firstProc) ss << ",";
        firstProc = false;
        const auto& list = groups[pid];
        ss << "{\"pid\":" << pid
           << ",\"process_name\":\"" << JsonEscape(list[0]->process_name) << "\""
           << ",\"windows\":[";
        bool firstWin = true;
        for (const auto* w : list) {
            if (!firstWin) ss << ",";
            firstWin = false;

            ss << "{\"hwnd\":\"0x" << std::hex << (unsigned long long)w->hwnd
               << "\"" << std::dec
               << ",\"z_order\":" << w->z_order
               << ",\"title\":\"" << JsonEscape(w->title) << "\""
               << ",\"rect\":{\"x\":" << w->rcWindow.left
               << ",\"y\":" << w->rcWindow.top
               << ",\"width\":" << (w->rcWindow.right - w->rcWindow.left)
               << ",\"height\":" << (w->rcWindow.bottom - w->rcWindow.top) << "}"
               << ",\"is_foreground\":" << (w->fg ? "true" : "false")
               << ",\"is_minimized\":" << (w->iconic ? "true" : "false");

            if (includeDetails) {
                ss << ",\"class_name\":\"" << JsonEscape(w->cls) << "\""
                   << ",\"client_rect\":{\"x\":" << w->rcClient.left
                   << ",\"y\":" << w->rcClient.top
                   << ",\"width\":" << (w->rcClient.right - w->rcClient.left)
                   << ",\"height\":" << (w->rcClient.bottom - w->rcClient.top) << "}"
                   << ",\"style\":\"0x" << std::hex << w->style << "\""
                   << ",\"exstyle\":\"0x" << w->exstyle << "\"" << std::dec
                   << ",\"window_status\":" << w->winStatus
                   << ",\"border\":{\"cx\":" << w->borderCX
                   << ",\"cy\":" << w->borderCY << "}"
                   << ",\"show_cmd\":" << w->showCmd
                   << ",\"normal_pos\":{\"x\":" << w->rcNormal.left
                   << ",\"y\":" << w->rcNormal.top
                   << ",\"width\":" << (w->rcNormal.right - w->rcNormal.left)
                   << ",\"height\":" << (w->rcNormal.bottom - w->rcNormal.top) << "}"
                   << ",\"parent\":\"0x" << std::hex
                   << (unsigned long long)w->parent << "\""
                   << ",\"owner\":\"0x" << (unsigned long long)w->owner
                   << "\"" << std::dec
                   << ",\"pid\":" << w->pid
                   << ",\"tid\":" << w->tid
                   << ",\"process_path\":\"" << JsonEscape(w->process_path) << "\""
                   << ",\"hinstance\":\"0x" << std::hex << w->hinstance
                   << "\"" << std::dec
                   << ",\"visible\":" << (w->visible ? "true" : "false")
                   << ",\"enabled\":" << (w->enabled ? "true" : "false")
                   << ",\"minimized\":" << (w->iconic ? "true" : "false")
                   << ",\"maximized\":" << (w->zoomed ? "true" : "false")
                   << ",\"topmost\":" << ((w->exstyle & WS_EX_TOPMOST) ? "true" : "false")
                   << ",\"layered\":" << ((w->exstyle & WS_EX_LAYERED) ? "true" : "false")
                   << ",\"tool_window\":" << ((w->exstyle & WS_EX_TOOLWINDOW) ? "true" : "false")
                   << ",\"cloaked\":" << (w->cloaked ? "true" : "false")
                   << ",\"dpi\":" << w->dpi
                   << ",\"window_type_atom\":" << w->atomType;
            }
            ss << "}";
        }
        ss << "]}";
    }
    ss << "]}";
    return ss.str();
}

} // namespace screen
} // namespace suspex
