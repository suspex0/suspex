// Registry gRPC service — thin wrapper over the Reg* API, with optional
// per-request impersonation of another user's token.
//
// Runs in the agent process context. Under the SuspexAgent service this
// is SYSTEM (full access to HKLM/HKU/HKCC + HKCU\S-1-5-18). Since v5 an
// `impersonate` field on the request lets a caller reach an arbitrary
// user's HKCU\<sid> hive by grabbing that user's primary token off a
// process they own and switching to it for the Reg* call.
//
// impersonate values:
//   ""                    -> agent's own token (default)
//   "user_by_pid:<pid>"   -> OpenProcess + OpenProcessToken on that pid
//   "user_by_sid:<sid>"   -> walk processes, pick the first owned by <sid>
//
// Needs SeImpersonatePrivilege — SYSTEM has it by default; --dev mode
// (unprivileged user) will get ERROR_ACCESS_DENIED here, which is the
// right answer.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "suspex.grpc.pb.h"

#include "services.hpp"

#include <windows.h>
#include <sddl.h>       // ConvertSidToStringSidA
#include <tlhelp32.h>   // CreateToolhelp32Snapshot for user_by_sid walk
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace suspex {

static HKEY MapHive(const std::string& name)
{
    if (name == "HKLM" || name == "HKEY_LOCAL_MACHINE") return HKEY_LOCAL_MACHINE;
    if (name == "HKCU" || name == "HKEY_CURRENT_USER") return HKEY_CURRENT_USER;
    if (name == "HKCR" || name == "HKEY_CLASSES_ROOT") return HKEY_CLASSES_ROOT;
    if (name == "HKU"  || name == "HKEY_USERS") return HKEY_USERS;
    if (name == "HKCC" || name == "HKEY_CURRENT_CONFIG") return HKEY_CURRENT_CONFIG;
    return nullptr;
}

static std::wstring Utf8To16(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static std::string Utf16To8(const wchar_t* s, size_t cch = (size_t)-1)
{
    if (!s) return {};
    if (cch == (size_t)-1) cch = wcslen(s);
    if (cch == 0) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s, (int)cch, nullptr, 0, nullptr, nullptr);
    std::string o((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, (int)cch, o.data(), n, nullptr, nullptr);
    return o;
}

static std::string WinErrText(LONG err)
{
    char buf[256] = {0};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, (DWORD)err, 0, buf, sizeof(buf) - 1, nullptr);
    std::string msg = buf;
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' '))
        msg.pop_back();
    if (msg.empty()) msg = "unknown error";
    return "gle=" + std::to_string((unsigned)err) + " " + msg;
}

// SHDeleteKey-equivalent: recursive delete via RegDeleteTreeW (documented,
// present on 6.1+). We keep the plain RegDeleteKeyExW path for non-recursive.
static LONG DeleteKey(HKEY root, const std::wstring& sub, REGSAM view, bool recursive)
{
    if (recursive) {
        HKEY h;
        LONG st = RegOpenKeyExW(root, sub.c_str(), 0, KEY_ALL_ACCESS | view, &h);
        if (st != ERROR_SUCCESS) return st;
        LONG tr = RegDeleteTreeW(h, nullptr); // wipe subtree
        RegCloseKey(h);
        if (tr != ERROR_SUCCESS) return tr;
        return RegDeleteKeyExW(root, sub.c_str(), view, 0);
    }
    return RegDeleteKeyExW(root, sub.c_str(), view, 0);
}

// ---------------------------------------------------------------- impersonation --

// Return the SID string of a process's primary token, or "" on failure.
// Used by user_by_sid to walk pids until we find one owned by the target.
static std::string ProcessTokenSid(DWORD pid)
{
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return {};
    HANDLE tok = nullptr;
    std::string result;
    if (OpenProcessToken(hp, TOKEN_QUERY, &tok)) {
        DWORD needed = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &needed);
        if (needed) {
            std::vector<BYTE> buf(needed);
            if (GetTokenInformation(tok, TokenUser, buf.data(), needed, &needed)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
                LPSTR s = nullptr;
                if (ConvertSidToStringSidA(tu->User.Sid, &s) && s) {
                    result = s;
                    LocalFree(s);
                }
            }
        }
        CloseHandle(tok);
    }
    CloseHandle(hp);
    return result;
}

// Open a duplicated impersonation-token for the target pid's primary token.
// Caller CloseHandle()s.
static HANDLE OpenImpersonationTokenFromPid(DWORD pid, std::string* err_out)
{
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) {
        *err_out = "OpenProcess(pid=" + std::to_string(pid) + ") " + WinErrText(GetLastError());
        return nullptr;
    }
    HANDLE primary = nullptr;
    if (!OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &primary)) {
        DWORD e = GetLastError();
        CloseHandle(hp);
        *err_out = "OpenProcessToken " + WinErrText(e);
        return nullptr;
    }
    CloseHandle(hp);
    HANDLE dup = nullptr;
    if (!DuplicateTokenEx(primary, TOKEN_IMPERSONATE | TOKEN_QUERY, nullptr,
                          SecurityImpersonation, TokenImpersonation, &dup)) {
        DWORD e = GetLastError();
        CloseHandle(primary);
        *err_out = "DuplicateTokenEx " + WinErrText(e);
        return nullptr;
    }
    CloseHandle(primary);
    return dup;
}

// user_by_sid: linear scan of running pids via CreateToolhelp32Snapshot.
// First hit wins. Slow-ish but correct; a per-session cache can come later.
static HANDLE OpenImpersonationTokenFromSid(const std::string& wanted_sid, std::string* err_out)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        *err_out = "CreateToolhelp32Snapshot " + WinErrText(GetLastError());
        return nullptr;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    HANDLE tok = nullptr;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue; // System
            std::string sid = ProcessTokenSid(pe.th32ProcessID);
            if (sid.empty()) continue;
            if (_stricmp(sid.c_str(), wanted_sid.c_str()) != 0) continue;
            std::string sub_err;
            tok = OpenImpersonationTokenFromPid(pe.th32ProcessID, &sub_err);
            if (tok) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!tok) {
        *err_out = "no accessible process owned by sid " + wanted_sid;
    }
    return tok;
}

// RAII scope: impersonate on construction, RevertToSelf on destruction.
// Failure state is exposed via ok() so callers can bail with a clean error.
class ImpersonationScope {
public:
    ImpersonationScope(const std::string& spec)
    {
        if (spec.empty()) {
            ok_ = true;
            return;
        }
        std::string err;
        HANDLE tok = nullptr;
        if (spec.rfind("user_by_pid:", 0) == 0) {
            DWORD pid = (DWORD)strtoul(spec.c_str() + 12, nullptr, 0);
            if (!pid) { err_ = "user_by_pid: invalid pid"; return; }
            tok = OpenImpersonationTokenFromPid(pid, &err);
        } else if (spec.rfind("user_by_sid:", 0) == 0) {
            std::string sid = spec.substr(12);
            if (sid.empty()) { err_ = "user_by_sid: empty sid"; return; }
            tok = OpenImpersonationTokenFromSid(sid, &err);
        } else {
            err_ = "unknown impersonate spec: " + spec;
            return;
        }
        if (!tok) {
            err_ = err.empty() ? "impersonation token acquisition failed" : err;
            return;
        }
        if (!ImpersonateLoggedOnUser(tok)) {
            DWORD e = GetLastError();
            CloseHandle(tok);
            err_ = "ImpersonateLoggedOnUser " + WinErrText(e);
            return;
        }
        CloseHandle(tok);
        active_ = true;
        ok_ = true;
    }
    ~ImpersonationScope()
    {
        if (active_) {
            RevertToSelf();
        }
    }
    ImpersonationScope(const ImpersonationScope&) = delete;
    ImpersonationScope& operator=(const ImpersonationScope&) = delete;
    bool ok() const { return ok_; }
    const std::string& error() const { return err_; }

private:
    bool ok_ = false;
    bool active_ = false;
    std::string err_;
};

class RegistrySvc final : public Registry::Service {
public:
    RegistrySvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status Get(::grpc::ServerContext* ctx, const RegGetRequest* req,
                     RegGetResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        HKEY root = MapHive(req->hive());
        if (!root) {
            FillStatus(resp, "unknown hive: " + req->hive());
            return grpc::Status::OK;
        }
        ImpersonationScope imp(req->impersonate());
        if (!imp.ok()) {
            FillStatus(resp, "impersonate: " + imp.error());
            return grpc::Status::OK;
        }
        REGSAM view = req->wow64_32() ? KEY_WOW64_32KEY : 0;
        HKEY h;
        std::wstring sub = Utf8To16(req->subkey());
        std::wstring val = Utf8To16(req->value());
        LONG st = RegOpenKeyExW(root, sub.c_str(), 0, KEY_READ | view, &h);
        if (st != ERROR_SUCCESS) {
            FillStatus(resp, "RegOpenKeyExW " + WinErrText(st));
            return grpc::Status::OK;
        }
        DWORD type = 0, size = 0;
        st = RegQueryValueExW(h, val.c_str(), nullptr, &type, nullptr, &size);
        if (st != ERROR_SUCCESS) {
            RegCloseKey(h);
            FillStatus(resp, "RegQueryValueExW(size) " + WinErrText(st));
            return grpc::Status::OK;
        }
        std::vector<BYTE> buf(size);
        st = RegQueryValueExW(h, val.c_str(), nullptr, &type, buf.data(), &size);
        RegCloseKey(h);
        if (st != ERROR_SUCCESS) {
            FillStatus(resp, "RegQueryValueExW(data) " + WinErrText(st));
            return grpc::Status::OK;
        }
        resp->set_type(type);
        resp->set_data(buf.data(), size);
        // Decode common types so the caller doesn't re-parse.
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            size_t cch = size / sizeof(wchar_t);
            if (cch && ((const wchar_t*)buf.data())[cch - 1] == L'\0') cch--;
            resp->set_data_str(Utf16To8((const wchar_t*)buf.data(), cch));
        } else if (type == REG_DWORD && size == 4) {
            DWORD v = 0;
            memcpy(&v, buf.data(), 4);
            resp->set_data_qword(v);
        } else if (type == REG_QWORD && size == 8) {
            uint64_t v = 0;
            memcpy(&v, buf.data(), 8);
            resp->set_data_qword(v);
        } else if (type == REG_MULTI_SZ && size >= sizeof(wchar_t)) {
            const wchar_t* p = (const wchar_t*)buf.data();
            size_t cch = size / sizeof(wchar_t);
            size_t i = 0;
            while (i < cch && p[i]) {
                size_t start = i;
                while (i < cch && p[i]) i++;
                resp->add_data_multi_sz(Utf16To8(p + start, i - start));
                if (i < cch) i++; // skip separator NUL
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Set(::grpc::ServerContext* ctx, const RegSetRequest* req,
                     RegSetResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        HKEY root = MapHive(req->hive());
        if (!root) {
            FillStatus(resp, "unknown hive: " + req->hive());
            return grpc::Status::OK;
        }
        ImpersonationScope imp(req->impersonate());
        if (!imp.ok()) {
            FillStatus(resp, "impersonate: " + imp.error());
            return grpc::Status::OK;
        }
        REGSAM view = req->wow64_32() ? KEY_WOW64_32KEY : 0;
        HKEY h;
        std::wstring sub = Utf8To16(req->subkey());
        std::wstring val = Utf8To16(req->value());
        LONG st;
        if (req->create_subkey()) {
            DWORD disp = 0;
            st = RegCreateKeyExW(root, sub.c_str(), 0, nullptr, 0,
                                 KEY_SET_VALUE | view, nullptr, &h, &disp);
        } else {
            st = RegOpenKeyExW(root, sub.c_str(), 0, KEY_SET_VALUE | view, &h);
        }
        if (st != ERROR_SUCCESS) {
            FillStatus(resp, "open/create " + WinErrText(st));
            return grpc::Status::OK;
        }
        const std::string& data = req->data();
        st = RegSetValueExW(h, val.c_str(), 0, req->type(),
                            (const BYTE*)data.data(), (DWORD)data.size());
        RegCloseKey(h);
        if (st != ERROR_SUCCESS) {
            FillStatus(resp, "RegSetValueExW " + WinErrText(st));
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Enum(::grpc::ServerContext* ctx, const RegEnumRequest* req,
                      RegEnumResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        HKEY root = MapHive(req->hive());
        if (!root) {
            FillStatus(resp, "unknown hive: " + req->hive());
            return grpc::Status::OK;
        }
        ImpersonationScope imp(req->impersonate());
        if (!imp.ok()) {
            FillStatus(resp, "impersonate: " + imp.error());
            return grpc::Status::OK;
        }
        REGSAM view = req->wow64_32() ? KEY_WOW64_32KEY : 0;
        HKEY h;
        LONG st = RegOpenKeyExW(root, Utf8To16(req->subkey()).c_str(), 0,
                                KEY_READ | view, &h);
        if (st != ERROR_SUCCESS) {
            FillStatus(resp, "RegOpenKeyExW " + WinErrText(st));
            return grpc::Status::OK;
        }
        if (req->want_subkeys()) {
            wchar_t name[256];
            for (DWORD i = 0;; i++) {
                DWORD cch = _countof(name);
                LONG en = RegEnumKeyExW(h, i, name, &cch, nullptr, nullptr, nullptr, nullptr);
                if (en == ERROR_NO_MORE_ITEMS) break;
                if (en != ERROR_SUCCESS) {
                    RegCloseKey(h);
                    FillStatus(resp, "RegEnumKeyExW " + WinErrText(en));
                    return grpc::Status::OK;
                }
                resp->add_subkeys(Utf16To8(name, cch));
            }
        }
        if (req->want_values()) {
            wchar_t name[16384]; // registry value-name max
            for (DWORD i = 0;; i++) {
                DWORD cch = _countof(name);
                DWORD type = 0, size = 0;
                LONG en = RegEnumValueW(h, i, name, &cch, nullptr, &type, nullptr, &size);
                if (en == ERROR_NO_MORE_ITEMS) break;
                if (en != ERROR_SUCCESS) {
                    RegCloseKey(h);
                    FillStatus(resp, "RegEnumValueW " + WinErrText(en));
                    return grpc::Status::OK;
                }
                auto* m = resp->add_values();
                m->set_name(Utf16To8(name, cch));
                m->set_type(type);
                m->set_size(size);
            }
        }
        RegCloseKey(h);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Delete(::grpc::ServerContext* ctx, const RegDeleteRequest* req,
                        RegDeleteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        HKEY root = MapHive(req->hive());
        if (!root) {
            FillStatus(resp, "unknown hive: " + req->hive());
            return grpc::Status::OK;
        }
        ImpersonationScope imp(req->impersonate());
        if (!imp.ok()) {
            FillStatus(resp, "impersonate: " + imp.error());
            return grpc::Status::OK;
        }
        REGSAM view = req->wow64_32() ? KEY_WOW64_32KEY : 0;
        LONG st;
        if (!req->value().empty()) {
            // value delete: RegDeleteValueW is the surgical path
            HKEY h;
            st = RegOpenKeyExW(root, Utf8To16(req->subkey()).c_str(), 0,
                               KEY_SET_VALUE | view, &h);
            if (st != ERROR_SUCCESS) {
                FillStatus(resp, "open " + WinErrText(st));
                return grpc::Status::OK;
            }
            st = RegDeleteValueW(h, Utf8To16(req->value()).c_str());
            RegCloseKey(h);
            if (st != ERROR_SUCCESS) {
                FillStatus(resp, "RegDeleteValueW " + WinErrText(st));
                return grpc::Status::OK;
            }
        } else {
            st = DeleteKey(root, Utf8To16(req->subkey()), view, req->recursive());
            if (st != ERROR_SUCCESS) {
                FillStatus(resp, "RegDeleteKeyExW " + WinErrText(st));
                return grpc::Status::OK;
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

void RegisterRegistryService(grpc::ServerBuilder& builder, const AgentConfig& cfg)
{
    static RegistrySvc svc(cfg);
    builder.RegisterService(&svc);
}

} // namespace suspex
