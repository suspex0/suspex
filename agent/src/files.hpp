#pragma once

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <cstdint>
#include <string>
#include <vector>

namespace suspex {

class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    bool Begin(std::string* err);
    bool Update(const void* data, size_t len);
    std::string FinishHex();

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<BYTE> obj_;
};

std::string Hex(const BYTE* data, size_t len);

std::string Sha256HexBuf(const void* data, size_t len);

struct FileEntry {
    std::wstring path;
    bool isDir = false;
    UINT64 size = 0;
    UINT64 mtimeUnix = 0;
};

bool ListDirTree(const std::wstring& root, bool recursive, uint32_t maxEntries,
                 std::vector<FileEntry>* out, std::string* err);

// default: move into trashDir with a unique suffix; hard delete only when
// hardDelete is set
bool DeleteSafe(const std::wstring& path, const std::wstring& trashDir, bool hardDelete,
                std::string* err);

// v14: content-read open with the widest sharing we can legally offer.
// Retries once with FILE_FLAG_BACKUP_SEMANTICS on ACL/sharing failures
// (backup-privileged opens clear some ACCESS_DENIED cases; they do NOT
// clear share-mode-0 — see LockedCopyViaVss). gle_out = last Win32 error
// (0 on success).
HANDLE OpenForReadEx(const std::wstring& path, DWORD* gle_out);

// The two GLEs a share-mode-0 writer produces on an open attempt.
inline bool IsSharingGle(DWORD gle)
{
    return gle == ERROR_SHARING_VIOLATION || gle == ERROR_LOCK_VIOLATION;
}

// v14: copy `src` to a unique temp file via `esentutl /y /vss` — the only
// supported usermode read of a share-mode-0 file (goes through a VSS
// snapshot, so bytes are point-in-time). Caller deletes the temp path.
// Requires VSS privilege; the agent's service/SYSTEM context has it.
bool LockedCopyViaVss(const std::wstring& src, std::wstring* out_path,
                      std::string* err);

// Hash a file, transparently falling back to a VSS shadow copy when the
// live file is share-locked. via_snapshot is set true when the digest is
// of the snapshot; gle_out = the first open's Win32 error.
std::string Sha256HexFile(const std::wstring& path,
                          DWORD* gle_out = nullptr,
                          bool* via_snapshot = nullptr);

} // namespace suspex
