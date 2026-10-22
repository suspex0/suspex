#include "config.hpp"
#include "common.h"

#include <shellapi.h>

namespace suspex {

std::wstring AgentConfig::ExeDir()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s = path;
    size_t pos = s.find_last_of(L'\\');
    return pos == std::wstring::npos ? L"." : s.substr(0, pos);
}

static std::wstring WideArg(const char* a)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, a, -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    if (n) {
        MultiByteToWideChar(CP_UTF8, 0, a, -1, w.data(), n);
    }
    return w;
}

AgentConfig AgentConfig::FromArgs(int argc, char** argv)
{
    AgentConfig c;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--port") {
            c.port = atoi(next().c_str());
        } else if (a == "--token") {
            c.token = next();
        } else if (a == "--driver") {
            c.driverPath = WideArg(next().c_str());
        } else if (a == "--mapper") {
            c.mapperPath = WideArg(next().c_str());
        } else if (a == "--allow-delete") {
            c.allowDelete = true;
        } else if (a == "--no-driver-ops") {
            c.allowDriverLoad = false;
            c.allowDriverUnload = false;
        }
    }
    if (c.driverPath.empty()) {
        c.driverPath = ExeDir() + L"\\suspex_driver.sys";
    }
    if (c.mapperPath.empty()) {
        c.mapperPath = ExeDir() + L"\\mapper.exe";
    }
    if (c.trashDir.empty()) {
        c.trashDir = ExeDir() + L"\\.suspex_trash";
    }
    return c;
}

} // namespace suspex
