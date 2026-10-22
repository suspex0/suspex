#include "files.hpp"
#include "common.h"

#include <chrono>
#include <cstdio>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace suspex {

std::string Hex(const BYTE* data, size_t len)
{
    static const char* d = "0123456789abcdef";
    std::string s(len * 2, '0');
    for (size_t i = 0; i < len; i++) {
        s[i * 2] = d[data[i] >> 4];
        s[i * 2 + 1] = d[data[i] & 0xF];
    }
    return s;
}

Sha256::Sha256() = default;

Sha256::~Sha256()
{
    if (hash_) {
        BCryptDestroyHash(hash_);
    }
    if (alg_) {
        BCryptCloseAlgorithmProvider(alg_, 0);
    }
}

bool Sha256::Begin(std::string* err)
{
    if (BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        *err = "BCryptOpenAlgorithmProvider failed";
        return false;
    }
    DWORD objLen = 0, cb = 0;
    BCryptGetProperty(alg_, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    obj_.resize(objLen);
    if (BCryptCreateHash(alg_, &hash_, obj_.data(), objLen, nullptr, 0, 0) != 0) {
        *err = "BCryptCreateHash failed";
        return false;
    }
    return true;
}

bool Sha256::Update(const void* data, size_t len)
{
    return BCryptHashData(hash_, (PUCHAR)data, (ULONG)len, 0) == 0;
}

std::string Sha256::FinishHex()
{
    if (!hash_) {
        return "";
    }
    BYTE digest[32];
    if (BCryptFinishHash(hash_, digest, sizeof(digest), 0) != 0) {
        return "";
    }
    BCryptDestroyHash(hash_);
    hash_ = nullptr;
    return Hex(digest, sizeof(digest));
}

std::string Sha256HexBuf(const void* data, size_t len)
{
    Sha256 h;
    std::string err;
    if (!h.Begin(&err) || !h.Update(data, len)) {
        return "";
    }
    return h.FinishHex();
}

static UINT64 FileTimeToUnix(const FILETIME& ft)
{
    ULARGE_INTEGER u{{ft.dwLowDateTime, ft.dwHighDateTime}};
    return (u.QuadPart - 116444736000000000ull) / 10000000ull;
}

bool ListDirTree(const std::wstring& root, bool recursive, uint32_t maxEntries,
                 std::vector<FileEntry>* out, std::string* err)
{
    std::vector<std::wstring> stack{root};
    while (!stack.empty() && out->size() < maxEntries) {
        std::wstring dir = stack.back();
        stack.pop_back();
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            continue;
        }
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) {
                continue;
            }
            FileEntry e;
            e.path = dir + L"\\" + fd.cFileName;
            e.isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            ULARGE_INTEGER sz{{fd.nFileSizeLow, fd.nFileSizeHigh}};
            e.size = sz.QuadPart;
            e.mtimeUnix = FileTimeToUnix(fd.ftLastWriteTime);
            out->push_back(e);
            if (e.isDir && recursive && out->size() < maxEntries) {
                stack.push_back(e.path);
            }
            if (out->size() >= maxEntries) {
                break;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return true;
}

bool DeleteSafe(const std::wstring& path, const std::wstring& trashDir, bool hardDelete,
                std::string* err)
{
    if (hardDelete) {
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            if (!RemoveDirectoryW(path.c_str())) {
                *err = Win32ErrorString("RemoveDirectory", GetLastError());
                return false;
            }
            return true;
        }
        if (!DeleteFileW(path.c_str())) {
            *err = Win32ErrorString("DeleteFile", GetLastError());
            return false;
        }
        return true;
    }
    CreateDirectoryW(trashDir.c_str(), nullptr);
    ULONGLONG tick = GetTickCount64();
    wchar_t name[64];
    swprintf_s(name, L"\\%llu_", tick);
    std::wstring dest = trashDir + name + PathFindFileNameW(path.c_str());
    if (!MoveFileW(path.c_str(), dest.c_str())) {
        *err = Win32ErrorString("MoveFile(trash)", GetLastError());
        return false;
    }
    return true;
}

HANDLE OpenForReadEx(const std::wstring& path, DWORD* gle_out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD gle = GetLastError();
    if (h == INVALID_HANDLE_VALUE &&
        (gle == ERROR_ACCESS_DENIED || IsSharingGle(gle))) {
        h = CreateFileW(path.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        gle = GetLastError();
    }
    if (gle_out) {
        *gle_out = (h == INVALID_HANDLE_VALUE) ? gle : 0;
    }
    return h;
}

bool LockedCopyViaVss(const std::wstring& src, std::wstring* out_path, std::string* err)
{
    wchar_t tmpdir[MAX_PATH]{};
    DWORD n = GetTempPathW(MAX_PATH, tmpdir);
    if (!n || n >= MAX_PATH) {
        *err = "GetTempPath failed";
        return false;
    }
    wchar_t tmp[MAX_PATH]{};
    swprintf_s(tmp, L"%s\\suspex_vss_%lu_%llu.tmp", tmpdir,
               (unsigned long)GetCurrentProcessId(),
               (unsigned long long)GetTickCount64());
    // esentutl /y <src> /vss /d <dst> /o — VSS snapshot copy, the supported
    // usermode path into share-mode-0 files. Bounded: 30 s cap.
    std::wstring cmd = L"esentutl.exe /y \"" + src + L"\" /vss /d \"" + tmp + L"\" /o";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back(L'\0');
    if (!CreateProcessW(nullptr, cmdbuf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        *err = Win32ErrorString("esentutl spawn", GetLastError());
        return false;
    }
    CloseHandle(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hProcess);
    if (wait != WAIT_OBJECT_0 || code != 0) {
        *err = "esentutl /vss copy failed exit=" + std::to_string(code) +
               (wait == WAIT_TIMEOUT ? " (timed out)" : "");
        DeleteFileW(tmp);
        return false;
    }
    *out_path = tmp;
    return true;
}

std::string Sha256HexFile(const std::wstring& path, DWORD* gle_out, bool* via_snapshot)
{
    DWORD gle = 0;
    HANDLE h = OpenForReadEx(path, &gle);
    std::wstring shadow;
    bool shadowed = false;
    if (h == INVALID_HANDLE_VALUE && IsSharingGle(gle)) {
        std::string verr;
        if (LockedCopyViaVss(path, &shadow, &verr)) {
            DWORD g2 = 0;
            h = OpenForReadEx(shadow, &g2);
            shadowed = (h != INVALID_HANDLE_VALUE);
        }
    }
    if (gle_out) {
        *gle_out = (h == INVALID_HANDLE_VALUE) ? gle : 0;
    }
    if (h == INVALID_HANDLE_VALUE) {
        if (!shadow.empty()) {
            DeleteFileW(shadow.c_str());
        }
        return "";
    }
    Sha256 sha;
    std::string err;
    if (!sha.Begin(&err)) {
        CloseHandle(h);
        if (!shadow.empty()) {
            DeleteFileW(shadow.c_str());
        }
        return "";
    }
    BYTE buf[64 * 1024];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n) {
        sha.Update(buf, n);
    }
    CloseHandle(h);
    if (!shadow.empty()) {
        DeleteFileW(shadow.c_str());
    }
    if (via_snapshot) {
        *via_snapshot = shadowed;
    }
    return sha.FinishHex();
}

} // namespace suspex
