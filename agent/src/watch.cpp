#include "watch.hpp"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>

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

uint32_t MemoryWatch::MaxWatches()      { return EnvU32(L"SUSPX_MAX_WATCHES", 8); }
uint32_t MemoryWatch::MinIntervalMs()   { return EnvU32(L"SUSPX_WATCH_MIN_MS", 10); }
uint32_t MemoryWatch::MaxDurationS()    { return EnvU32(L"SUSPX_WATCH_MAX_DURATION", 600); }
uint32_t MemoryWatch::FailLimit()       { return EnvU32(L"SUSPX_WATCH_FAIL_LIMIT", 5); }

bool MemoryWatch::TryAcquire()
{
    std::lock_guard<std::mutex> lock(m_);
    if (active_ >= MaxWatches()) return false;
    ++active_;
    return true;
}

void MemoryWatch::Release()
{
    std::lock_guard<std::mutex> lock(m_);
    if (active_) --active_;
}

static uint64_t NowMs()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

std::string MemoryWatch::RunOnce(DriverMgr& drv, const WatchSpec& spec,
                                  const std::function<bool(const WatchEventLite&)>& emit,
                                  const std::function<bool()>& cancelled)
{
    if (spec.length == 0 || spec.length > 256) {
        return "watch: length must be 1..256 bytes";
    }
    if (!spec.expected.empty() && spec.expected.size() != spec.length) {
        return "watch: expected_hex length must match `length` when non-empty";
    }
    uint32_t interval = std::max<uint32_t>(spec.interval_ms, MinIntervalMs());
    uint32_t duration = spec.duration_s ? spec.duration_s : 60;
    duration = std::min<uint32_t>(duration, MaxDurationS());
    uint32_t max_events = spec.max_events;
    uint32_t fail_limit = FailLimit();

    std::vector<BYTE> prev;
    std::vector<BYTE> cur(spec.length);
    uint64_t seq = 0;
    uint64_t started_ms = NowMs();
    uint32_t consec_fails = 0;
    bool first_sample = true;

    while (true) {
        if (cancelled && cancelled()) {
            WatchEventLite eof{};
            eof.seq = seq + 1;
            eof.ts_ms = NowMs();
            eof.eof = true;
            eof.reason = "cancelled";
            emit(eof);
            return "";
        }
        if (NowMs() - started_ms >= (uint64_t)duration * 1000ULL) {
            WatchEventLite eof{};
            eof.seq = seq + 1;
            eof.ts_ms = NowMs();
            eof.eof = true;
            eof.reason = "duration";
            emit(eof);
            return "";
        }

        SIZE_T got = 0;
        bool ok = drv.Comm().MemRead(spec.space, spec.pid, spec.address,
                                     cur.data(), cur.size(), &got);
        if (!ok || got != cur.size()) {
            ++consec_fails;
            if (consec_fails >= fail_limit) {
                WatchEventLite eof{};
                eof.seq = ++seq;
                eof.ts_ms = NowMs();
                eof.read_failed = true;
                eof.prev = prev;
                eof.eof = true;
                eof.reason = "read_failed";
                emit(eof);
                return "";
            }
        } else {
            consec_fails = 0;
            bool changed = false;
            if (first_sample) {
                changed = true;
                first_sample = false;
            } else {
                changed = (cur != prev);
            }
            bool triggers = false;
            if (spec.expected.empty()) {
                triggers = changed;
            } else {
                triggers = (cur != spec.expected);
            }
            if (triggers) {
                WatchEventLite ev{};
                ev.seq = ++seq;
                ev.ts_ms = NowMs();
                ev.prev = prev;
                ev.now = cur;
                if (!emit(ev)) {
                    // downstream is dead — bail
                    return "";
                }
                if (max_events && seq >= max_events) {
                    WatchEventLite eof{};
                    eof.seq = seq + 1;
                    eof.ts_ms = NowMs();
                    eof.eof = true;
                    eof.reason = "max_events";
                    emit(eof);
                    return "";
                }
            }
            prev = cur;
        }
        Sleep(interval);
    }
}

MemoryWatch& WatchInstance()
{
    static MemoryWatch inst;
    return inst;
}

} // namespace suspex
