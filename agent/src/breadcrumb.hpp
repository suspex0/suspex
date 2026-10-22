// Agent-side driver-op breadcrumb: persistent last-N ring under
// %ProgramData%\suspex\breadcrumb.bin so a caller can ask "what was
// in flight when you died" even after SCM's 3-restart budget burned.
//
// Public surface:
//   Breadcrumb::Init() — must be called once at agent startup. Loads the
//                        prior lifetime's ring into PriorSnapshot() and
//                        starts a fresh in-memory ring for this run.
//   Breadcrumb::OnPre(ioctl, arg_summary) -> id
//   Breadcrumb::OnPost(id, status_kind, status_code)
//   Breadcrumb::CurrentSnapshot() / PriorSnapshot() — for RecentOps RPC.
//
// Persistence: after every OnPost we write the ring to disk in one
// go (rings are tiny — 64 entries * ~200 bytes each). Debounced to at
// most one write per 100 ms; a pending flush is coalesced by a
// worker thread so the RPC path never blocks on FlushFileBuffers.

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace suspex {

struct BreadcrumbEntry {
    uint64_t t_start_us;      // microseconds since agent start (QPC)
    uint64_t t_end_us;        // 0 if still pending / wedged
    uint32_t ioctl_code;
    uint32_t status_code;     // NTSTATUS or GLE
    char     status_kind[16]; // "pending" | "ok" | "error" | "wedged"
    char     arg_summary[192];
};

class Breadcrumb {
public:
    static constexpr size_t kCap = 64;

    // Initialise once at agent startup. Safe to call twice (no-op after first).
    // Returns true on success.
    static bool Init();

    // Called BEFORE issuing the IOCTL. Returns an opaque id used to close
    // the same slot in OnPost.
    static uint64_t OnPre(uint32_t ioctl_code, const std::string& arg_summary);

    // Called AFTER the IOCTL (or in an error handler). If OnPost never runs
    // for an id — say because the process died — that slot stays "pending"
    // in the on-disk ring, and PriorSnapshot() from the next lifetime
    // upgrades it to "wedged" during load.
    static void OnPost(uint64_t id, const char* status_kind, uint32_t status_code);

    // Snapshot of the current run's ring (chronological).
    static std::vector<BreadcrumbEntry> CurrentSnapshot();

    // Snapshot of the ring loaded from the previous lifetime's file
    // (chronological). Empty on the very first run.
    static std::vector<BreadcrumbEntry> PriorSnapshot();

    // Agent-start / now wall-clock timestamps in epoch ms.
    static uint64_t AgentStartEpochMs();
    static uint64_t NowEpochMs();

    // Flush the current ring to disk right now (blocking). Called by
    // the SCM stop handler so a clean shutdown loses nothing.
    static void FlushSync();
};

} // namespace suspex
