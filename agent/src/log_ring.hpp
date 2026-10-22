#pragma once

// v7: kernel-log rotation policy + agent-local LogTail primitive.
//
// The developer feedback that seeded ABI v7 hit a 234 MB unbounded
// kernel-log growth. Two fixes ship together:
//   * LogRing::TryRotate() — called opportunistically before the driver
//     writes; if the on-disk size exceeds the configured cap, renames
//     <path> → <path>.old (overwriting any prior .old) and lets the next
//     driver open recreate the primary. Zero-copy, no truncate — the
//     next driver-side write reopens the file fresh.
//   * LogRing::Tail() — pure Win32 CreateFile / SetFilePointerEx / ReadFile
//     against the on-disk file. FILE_SHARE_READ|WRITE|DELETE so the
//     kernel logger keeps writing while we read the tail.

#include <windows.h>

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace suspex {

struct LogTailResult {
    bool ok = false;
    std::string error;
    std::vector<BYTE> data;
    uint64_t total_size = 0;
    uint64_t tail_offset = 0;
    bool truncated = false;
    uint64_t rotated_size = 0;  // populated when include_rotated=true
    // v14: content came from a VSS shadow copy — live file is share-mode-0
    // locked and bytes are a point-in-time snapshot.
    bool via_shadow = false;
    // v14: Win32 error of the failed open when ok==false (0 when N/A) —
    // lets the orchestrator classify sharing_locked vs missing vs denied
    // without parsing the error text.
    uint32_t open_gle = 0;
};

// v8: streamed tail. Each chunk shows the caller a slice of the file plus
// its absolute offset; a `rotated=true` chunk means we reopened the file
// after a size-shrink (log_ring rotated <path> -> <path>.old).
struct FollowChunkLite {
    uint64_t offset = 0;
    std::vector<BYTE> data;
    bool rotated = false;
    uint64_t new_total_size = 0;
    // v14: stat-degraded chunk — file can't be opened (share-mode-0 lock or
    // not yet created), so this reports a size/mtime change only; data is
    // always empty. Follow auto-upgrades to content chunks when the open
    // succeeds.
    bool stat_only = false;
};

class LogRing {
public:
    // Configure the rotation policy. `max_bytes` = 0 disables rotation.
    // Env override: SUSPX_KERNEL_LOG_MAX_MB.
    static void Configure(const std::wstring& primary_path, uint64_t max_bytes);

    // Best-effort rotate: rename <primary> → <primary>.old when the
    // on-disk file is bigger than the cap. Called by service init and
    // whenever a caller wants to trim before a large log-tail request.
    // Returns true if a rotation happened (log written / status only).
    static bool TryRotate(std::string* err = nullptr);

    // Read up to `bytes` from the tail of `path`. `line_align`: skip
    // partial first line so response is line-clean. `include_rotated`:
    // also tail <path>.old (append with a "--- rotated ---" marker into
    // the result's rotated size field; the .old bytes are prepended into
    // `data` for the caller's convenience).
    static LogTailResult Tail(const std::wstring& path, uint32_t bytes,
                              bool from_end, bool line_align,
                              bool include_rotated);

    // v8: `tail -f` primitive. Opens the file with the same FILE_SHARE
    // flags Tail() uses, seeks per `from_offset` / `initial_tail_bytes`,
    // then polls for growth. `emit` is called from THIS thread for each
    // chunk; return false to bail. `cancelled` is polled between iterations
    // so a gRPC ServerContext::IsCancelled() propagates immediately.
    // Returns the terminal reason ("duration" / "cancelled" / "io_error" /
    // "path_gone" / "max_bytes" / ""); an empty return means the terminal
    // reason was already surfaced by an emit() returning false (client
    // stream dead) — the caller supplies its own reason in that case.
    //
    // `from_offset == UINT64_MAX` starts at the current EOF.
    // `follow_rotation` reopens the primary path when the size shrinks.
    //   (log_ring.TryRotate renames primary -> primary.old; the follower
    //   emits a rotated=true marker, resets cursor to 0, and continues.)
    static constexpr uint64_t kFromEnd = 0xFFFFFFFFFFFFFFFFULL;
    static std::string Follow(const std::wstring& path,
                              uint64_t from_offset,
                              uint32_t initial_tail_bytes,
                              uint32_t poll_interval_ms,
                              uint32_t max_chunk_bytes,
                              bool line_align,
                              bool follow_rotation,
                              uint32_t duration_s,
                              uint64_t max_bytes,
                              const std::function<bool(const FollowChunkLite&)>& emit,
                              const std::function<bool()>& cancelled);

private:
    static std::wstring primary_path_;
    static uint64_t max_bytes_;
};

// v8: concurrency gate for LogFollow — one worker per active follow, capped
// at SUSPX_MAX_FOLLOWS (default 8). Same shape as MemoryWatch's TryAcquire /
// Release so a runaway MCP client can't spin up one follower per file in a
// scripts/ tree.
class LogFollowGate {
public:
    static uint32_t MaxFollows();     // SUSPX_MAX_FOLLOWS (default 8)
    static uint32_t MaxDurationS();   // SUSPX_FOLLOW_MAX_DURATION (default 3600)
    static uint32_t MinIntervalMs();  // SUSPX_FOLLOW_MIN_MS (default 10)

    bool TryAcquire();
    void Release();

private:
    std::mutex m_;
    uint32_t active_ = 0;
};

LogFollowGate& FollowInstance();

} // namespace suspex
