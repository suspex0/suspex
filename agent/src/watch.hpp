#pragma once

// v7: agent-side memory-change watcher.
//
// The developer feedback (2026-09-09) had to poll a cookie address from
// their own harness because there was no primitive on the agent for
// "read this address every X ms and tell me when it changes." MemoryWatch
// fills that gap:
//   * One worker thread per active watch (bounded by SUSPX_MAX_WATCHES,
//     default 8) — never accepts more.
//   * Each thread MemReads `length` bytes via Driver::MemRead (same
//     routing as Memory.Read: user/kernel/physical), compares against
//     the previous window, and emits a WatchEvent on transition.
//   * Interval floor (SUSPX_WATCH_MIN_MS, default 10 ms) so a runaway
//     request cannot turn the target into a busy loop.
//   * Terminates on: duration_s elapsed, max_events reached, client
//     stream cancelled, agent shutdown, or N consecutive read failures
//     (default 5 — wedge detection; last event's read_failed=true).
// The watcher lives entirely in the agent process. There is no on-disk
// buffer, no cross-run persistence — the plan explicitly ruled that out
// as a separate cycle. Watches die with the client.

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "suspex_comm.h"
#include "driver_mgr.hpp"

namespace suspex {

struct WatchSpec {
    Space space = Space::User;
    uint32_t pid = 0;
    uint64_t address = 0;
    uint32_t length = 0;
    uint32_t interval_ms = 0;
    uint32_t duration_s = 0;
    std::vector<BYTE> expected;   // empty = report every change
    uint32_t max_events = 0;
    std::string tag;
};

struct WatchEventLite {
    uint64_t seq = 0;
    uint64_t ts_ms = 0;
    std::vector<BYTE> prev;
    std::vector<BYTE> now;
    bool read_failed = false;
    bool eof = false;
    std::string reason;
};

class MemoryWatch {
public:
    // Static caps read from env at first use.
    //   SUSPX_MAX_WATCHES        (default 8)
    //   SUSPX_WATCH_MIN_MS       (default 10)
    //   SUSPX_WATCH_MAX_DURATION (default 600  = 10 minutes)
    //   SUSPX_WATCH_FAIL_LIMIT   (default 5)
    static uint32_t MaxWatches();
    static uint32_t MinIntervalMs();
    static uint32_t MaxDurationS();
    static uint32_t FailLimit();

    // Run one watch synchronously (called from the gRPC streaming handler
    // on the RPC's own thread). `emit` is called from this thread with
    // the current event; return false to signal cancellation. Returns
    // an error string on failure (empty on clean end).
    std::string RunOnce(DriverMgr& drv, const WatchSpec& spec,
                        const std::function<bool(const WatchEventLite&)>& emit,
                        const std::function<bool()>& cancelled);

    // Concurrency gate — call before RunOnce and pair with Release. Uses
    // a plain semaphore so the count is honest across all RPC threads.
    bool TryAcquire();
    void Release();

private:
    std::mutex m_;
    uint32_t active_ = 0;
};

// Singleton — the gRPC service holds one via reference.
MemoryWatch& WatchInstance();

} // namespace suspex
