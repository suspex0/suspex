#pragma once

#include "build_version.h"

#define SUSPEX_AGENT_VERSION "0.31.0+" SUSPEX_GIT_SHA SUSPEX_GIT_DIRTY

#include <windows.h>
#include <string>

namespace suspex {

inline std::string Win32ErrorString(const char* what, DWORD gle)
{
    char msg[256]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, gle,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, sizeof(msg), nullptr);
    std::string s = what;
    s += " (";
    s += std::to_string((unsigned long)gle);
    s += ") ";
    s += msg;
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
    return s;
}

inline UINT64 NowUnix()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{{ft.dwLowDateTime, ft.dwHighDateTime}};
    return (u.QuadPart - 116444736000000000ull) / 10000000ull;
}

} // namespace suspex
