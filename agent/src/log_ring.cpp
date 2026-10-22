#include "log_ring.hpp"
#include "files.hpp"
#include "common.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace suspex {

static uint32_t EnvU32(const wchar_t* name, uint32_t fallback)
{
    wchar_t buf[32] = {};
    DWORD n = GetEnvironmentVariableW(name, buf,
                                      (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return fallback;
    uint64_t v = 0;
    for (DWORD i = 0; i < n; ++i) {
        if (buf[i] < L'0' || buf[i] > L'9') return fallback;
        v = v * 10 + (uint64_t)(buf[i] - L'0');
        if (v > 0xFFFFFFFFULL) return 0xFFFFFFFFu;
    }
    return (uint32_t)v;
}

std::wstring LogRing::primary_path_;
uint64_t LogRing::max_bytes_ = 0;

// Env-var override; called from Configure. Silently caps to 4 GiB to
// keep the rotation path sane.
static uint64_t ParseEnvMaxBytes(uint64_t fallback)
{
    wchar_t buf[64] = {};
    DWORD n = GetEnvironmentVariableW(L"SUSPX_KERNEL_LOG_MAX_MB", buf,
                                      (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) {
        return fallback;
    }
    uint64_t mb = 0;
    for (DWORD i = 0; i < n; ++i) {
        if (buf[i] < L'0' || buf[i] > L'9') return fallback;
        mb = mb * 10 + (uint64_t)(buf[i] - L'0');
        if (mb > 4096) return 4096ULL * 1024 * 1024;
    }
    return mb * 1024 * 1024;
}

uint32_t LogFollowGate::MaxFollows()    { return EnvU32(L"SUSPX_MAX_FOLLOWS", 8); }
uint32_t LogFollowGate::MaxDurationS()  { return EnvU32(L"SUSPX_FOLLOW_MAX_DURATION", 3600); }
uint32_t LogFollowGate::MinIntervalMs() { return EnvU32(L"SUSPX_FOLLOW_MIN_MS", 10); }

bool LogFollowGate::TryAcquire()
{
    std::lock_guard<std::mutex> lock(m_);
    if (active_ >= MaxFollows()) return false;
    ++active_;
    return true;
}

void LogFollowGate::Release()
{
    std::lock_guard<std::mutex> lock(m_);
    if (active_) --active_;
}

LogFollowGate& FollowInstance()
{
    static LogFollowGate inst;
    return inst;
}

void LogRing::Configure(const std::wstring& primary_path, uint64_t max_bytes)
{
    primary_path_ = primary_path;
    // Default 64 MiB. Env override wins so operators can raise the cap
    // for a long capture run without a rebuild.
    max_bytes_ = ParseEnvMaxBytes(max_bytes ? max_bytes : (64ULL * 1024 * 1024));
}

static bool StatSize(const std::wstring& path, uint64_t* size_out)
{
    WIN32_FILE_ATTRIBUTE_DATA a{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) {
        return false;
    }
    if (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    ULARGE_INTEGER u{};
    u.LowPart = a.nFileSizeLow;
    u.HighPart = a.nFileSizeHigh;
    *size_out = u.QuadPart;
    return true;
}

bool LogRing::TryRotate(std::string* err)
{
    if (primary_path_.empty() || max_bytes_ == 0) {
        return false;
    }
    uint64_t sz = 0;
    if (!StatSize(primary_path_, &sz)) return false;
    if (sz <= max_bytes_) return false;
    std::wstring rotated = primary_path_ + L".old";
    // Replace any prior .old, tolerating missing target.
    DeleteFileW(rotated.c_str());
    if (!MoveFileExW(primary_path_.c_str(), rotated.c_str(),
                     MOVEFILE_REPLACE_EXISTING)) {
        if (err) {
            char msg[128];
            _snprintf_s(msg, _TRUNCATE, "MoveFileExW rotate failed gle=%lu",
                        GetLastError());
            *err = msg;
        }
        return false;
    }
    return true;
}

LogTailResult LogRing::Tail(const std::wstring& path, uint32_t bytes,
                            bool from_end, bool line_align,
                            bool include_rotated)
{
    LogTailResult r;
    if (bytes == 0) bytes = 64 * 1024;
    if (bytes > 4 * 1024 * 1024) bytes = 4 * 1024 * 1024;  // 4 MiB per call

    DWORD open_gle = 0;
    HANDLE h = OpenForReadEx(path, &open_gle);
    std::wstring shadow_tmp;
    if (h == INVALID_HANDLE_VALUE && IsSharingGle(open_gle)) {
        // v14: share-mode-0 lock — the only usermode read path is a VSS
        // shadow copy. Content comes back point-in-time; flag it so the
        // caller doesn't treat the snapshot as the live file.
        std::string verr;
        if (LockedCopyViaVss(path, &shadow_tmp, &verr)) {
            DWORD g2 = 0;
            h = OpenForReadEx(shadow_tmp, &g2);
        }
        if (h == INVALID_HANDLE_VALUE) {
            r.open_gle = open_gle;
            r.error = "sharing_locked: file is share-mode-0 locked "
                      "(gle=" + std::to_string(open_gle) + ") and the VSS "
                      "shadow-copy fallback failed: " + verr;
            return r;
        }
        r.via_shadow = true;
    } else if (h == INVALID_HANDLE_VALUE) {
        r.open_gle = open_gle;
        r.error = Win32ErrorString("CreateFileW(open for read)", open_gle);
        return r;
    }
    struct ShadowCleanup {
        const std::wstring& p;
        ~ShadowCleanup() { if (!p.empty()) DeleteFileW(p.c_str()); }
    } shadow_guard{shadow_tmp};

    LARGE_INTEGER size_li{};
    if (!GetFileSizeEx(h, &size_li)) {
        CloseHandle(h);
        char msg[128];
        _snprintf_s(msg, _TRUNCATE, "GetFileSizeEx failed gle=%lu",
                    GetLastError());
        r.error = msg;
        return r;
    }
    r.total_size = (uint64_t)size_li.QuadPart;

    uint32_t want = bytes;
    if ((uint64_t)want > r.total_size) want = (uint32_t)r.total_size;

    uint64_t offset = 0;
    if (from_end && r.total_size > want) {
        offset = r.total_size - want;
    }
    r.tail_offset = offset;
    r.truncated = offset > 0 || (from_end && want < r.total_size);

    LARGE_INTEGER seek{};
    seek.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, seek, nullptr, FILE_BEGIN)) {
        CloseHandle(h);
        char msg[128];
        _snprintf_s(msg, _TRUNCATE, "SetFilePointerEx failed gle=%lu",
                    GetLastError());
        r.error = msg;
        return r;
    }

    r.data.resize(want);
    DWORD got = 0;
    BOOL ok = ReadFile(h, r.data.data(), (DWORD)want, &got, nullptr);
    CloseHandle(h);
    if (!ok) {
        char msg[128];
        _snprintf_s(msg, _TRUNCATE, "ReadFile failed gle=%lu",
                    GetLastError());
        r.error = msg;
        r.data.clear();
        return r;
    }
    r.data.resize(got);

    // Skip the first (partial) line so the tail is line-clean.
    if (line_align && offset > 0 && !r.data.empty()) {
        auto it = std::find(r.data.begin(), r.data.end(), (BYTE)'\n');
        if (it != r.data.end()) {
            r.data.erase(r.data.begin(), it + 1);
        }
    }

    // Optional rotated tail — same treatment on <path>.old.
    if (include_rotated) {
        std::wstring rotated = path + L".old";
        uint64_t rot_size = 0;
        if (StatSize(rotated, &rot_size) && rot_size > 0) {
            r.rotated_size = rot_size;
            LogTailResult r2 = Tail(rotated, bytes, from_end, line_align, false);
            if (r2.ok || !r2.data.empty()) {
                // Prepend rotated data + separator into `data`. Keeps the
                // response self-descriptive to a caller who forgot they
                // asked for the rotated file.
                std::string marker = "\n--- rotated ---\n";
                std::vector<BYTE> merged;
                merged.reserve(r2.data.size() + marker.size() + r.data.size());
                merged.insert(merged.end(), r2.data.begin(), r2.data.end());
                merged.insert(merged.end(), (const BYTE*)marker.data(),
                              (const BYTE*)marker.data() + marker.size());
                merged.insert(merged.end(), r.data.begin(), r.data.end());
                r.data = std::move(merged);
            }
        }
    }

    r.ok = true;
    return r;
}

namespace {

HANDLE OpenShared(const std::wstring& path)
{
    return CreateFileW(path.c_str(), GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

// Seek `h` to `offset` from the start; returns true on success.
bool SeekTo(HANDLE h, uint64_t offset)
{
    LARGE_INTEGER li{};
    li.QuadPart = (LONGLONG)offset;
    return SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0;
}

uint64_t FileSize(HANDLE h)
{
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) return 0;
    return (uint64_t)sz.QuadPart;
}

} // namespace

std::string LogRing::Follow(const std::wstring& path,
                            uint64_t from_offset,
                            uint32_t initial_tail_bytes,
                            uint32_t poll_interval_ms,
                            uint32_t max_chunk_bytes,
                            bool line_align,
                            bool follow_rotation,
                            uint32_t duration_s,
                            uint64_t max_bytes,
                            const std::function<bool(const FollowChunkLite&)>& emit,
                            const std::function<bool()>& cancelled)
{
    const uint32_t poll_floor = LogFollowGate::MinIntervalMs();
    const uint32_t duration_cap = LogFollowGate::MaxDurationS();
    uint32_t poll = poll_interval_ms ? std::max(poll_interval_ms, poll_floor) : 200;
    uint32_t duration = duration_s ? std::min(duration_s, duration_cap) : 600;
    uint32_t chunk_cap = max_chunk_bytes ? max_chunk_bytes : 64 * 1024;
    if (chunk_cap > 4 * 1024 * 1024) chunk_cap = 4 * 1024 * 1024;

    HANDLE h = OpenShared(path);
    DWORD open_gle = GetLastError();
    // v14 stat-follow degrade: a share-mode-0 lock (or a file that doesn't
    // exist yet — subscribers often arrive before the writer) no longer
    // kills the follow. Instead we emit stat_only chunks on size/mtime
    // change and retry the real open every poll, upgrading to content
    // chunks the moment it succeeds. Anything else still fails fast.
    bool stat_mode = false;
    if (h == INVALID_HANDLE_VALUE) {
        if (IsSharingGle(open_gle) || open_gle == ERROR_FILE_NOT_FOUND ||
            open_gle == ERROR_PATH_NOT_FOUND || open_gle == ERROR_ACCESS_DENIED) {
            stat_mode = true;
        } else {
            char msg[160];
            _snprintf_s(msg, _TRUNCATE, "CreateFileW('%ws') gle=%lu",
                        path.c_str(), open_gle);
            return std::string("io_error: ") + msg;
        }
    }

    uint64_t total = 0;
    uint64_t cursor = 0;
    if (!stat_mode) {
        total = FileSize(h);
        if (from_offset == kFromEnd) {
            cursor = total;
        } else if (from_offset == 0 && initial_tail_bytes) {
            cursor = total > initial_tail_bytes ? total - initial_tail_bytes : 0;
        } else {
            cursor = from_offset > total ? total : from_offset;
        }
        if (!SeekTo(h, cursor)) {
            CloseHandle(h);
            return "io_error: initial seek failed";
        }
    }

    auto started = std::chrono::steady_clock::now();
    uint64_t emitted_bytes = 0;
    uint32_t consecutive_missing = 0;
    std::vector<BYTE> buf;
    buf.resize(chunk_cap);
    std::vector<BYTE> carry;  // for line_align: partial trailing line

    uint64_t stat_size = 0, stat_mtime = 0;
    bool stat_announced = false;

    while (true) {
        if (cancelled && cancelled()) {
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
            return "cancelled";
        }
        auto elapsed = std::chrono::steady_clock::now() - started;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
            >= (int64_t)duration) {
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
            return "duration";
        }

        // ---- stat-degraded mode (locked / not-yet-created file) ----
        if (stat_mode) {
            WIN32_FILE_ATTRIBUTE_DATA a{};
            if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) {
                ULARGE_INTEGER u{a.nFileSizeLow, a.nFileSizeHigh};
                ULARGE_INTEGER m{a.ftLastWriteTime.dwLowDateTime,
                                 a.ftLastWriteTime.dwHighDateTime};
                if (!stat_announced || u.QuadPart != stat_size ||
                    m.QuadPart != stat_mtime) {
                    stat_size = u.QuadPart;
                    stat_mtime = m.QuadPart;
                    stat_announced = true;
                    FollowChunkLite c{};
                    c.stat_only = true;
                    c.new_total_size = stat_size;
                    if (!emit(c)) {
                        return "";  // caller-signalled cancel
                    }
                }
            }
            // Retry the real open every poll — the lock may have cleared
            // or the file may finally exist.
            HANDLE try_h = OpenShared(path);
            if (try_h != INVALID_HANDLE_VALUE) {
                h = try_h;
                stat_mode = false;
                total = FileSize(h);
                cursor = total;  // resume at EOF: content the caller
                                 // missed during the lock is a tail away
                if (!SeekTo(h, cursor)) {
                    CloseHandle(h);
                    return "io_error: seek after stat-mode upgrade failed";
                }
                FollowChunkLite up{};
                up.offset = cursor;
                up.new_total_size = total;
                if (!emit(up)) {
                    CloseHandle(h);
                    return "";
                }
                continue;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(poll));
            continue;
        }

        uint64_t now_size = FileSize(h);

        // Detect rotation: size shrank below our cursor (someone renamed the
        // primary and a fresh one was created), or size shrank AND from_offset
        // wasn't UINT64_MAX (a truncate-in-place). Reopen and continue.
        if (follow_rotation && now_size < cursor) {
            CloseHandle(h);
            h = OpenShared(path);
            if (h == INVALID_HANDLE_VALUE) {
                if (++consecutive_missing >= 2) {
                    return "path_gone";
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(poll));
                h = OpenShared(path);
                if (h == INVALID_HANDLE_VALUE) return "path_gone";
            }
            consecutive_missing = 0;
            cursor = 0;
            if (!SeekTo(h, 0)) {
                CloseHandle(h);
                return "io_error: seek after rotation failed";
            }
            FollowChunkLite rot{};
            rot.rotated = true;
            rot.offset = 0;
            rot.new_total_size = FileSize(h);
            if (!emit(rot)) {
                CloseHandle(h);
                return "";  // caller-signalled cancel
            }
            continue;
        }

        if (now_size <= cursor) {
            std::this_thread::sleep_for(std::chrono::milliseconds(poll));
            continue;
        }

        uint64_t avail = now_size - cursor;
        DWORD want = (DWORD)std::min<uint64_t>(avail, chunk_cap);
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr)) {
            DWORD gle = GetLastError();
            CloseHandle(h);
            char msg[160];
            _snprintf_s(msg, _TRUNCATE, "ReadFile gle=%lu", gle);
            return std::string("io_error: ") + msg;
        }
        if (got == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(poll));
            continue;
        }

        FollowChunkLite chunk{};
        chunk.offset = cursor;
        chunk.new_total_size = now_size;

        if (line_align) {
            // Emit up to the last '\n' this batch; the trailing partial line
            // sticks with `carry` until the next iteration.
            size_t last_nl = SIZE_MAX;
            for (size_t i = got; i-- > 0; ) {
                if (buf[i] == (BYTE)'\n') { last_nl = i; break; }
            }
            if (last_nl == SIZE_MAX) {
                // No newline in this batch — hold everything until we see one,
                // but advance the cursor so we don't re-read the same bytes.
                carry.insert(carry.end(), buf.data(), buf.data() + got);
                cursor += got;
                std::this_thread::sleep_for(std::chrono::milliseconds(poll));
                continue;
            }
            // Emit carry + [0..last_nl+1); stash the tail.
            chunk.data.reserve(carry.size() + last_nl + 1);
            chunk.data.insert(chunk.data.end(), carry.begin(), carry.end());
            chunk.data.insert(chunk.data.end(), buf.data(), buf.data() + last_nl + 1);
            chunk.offset = cursor - carry.size();
            carry.assign(buf.data() + last_nl + 1, buf.data() + got);
            cursor += got;
        } else {
            chunk.data.assign(buf.data(), buf.data() + got);
            cursor += got;
        }

        if (!chunk.data.empty()) {
            if (!emit(chunk)) {
                CloseHandle(h);
                return "";
            }
            emitted_bytes += chunk.data.size();
        }

        if (max_bytes && emitted_bytes >= max_bytes) {
            CloseHandle(h);
            return "max_bytes";
        }
    }
}

} // namespace suspex
