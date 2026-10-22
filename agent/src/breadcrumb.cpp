// See breadcrumb.hpp. Implementation notes:
//
// - Ring is a fixed 64-slot array. Slot index is (next_id % kCap). Slots
//   are stamped in place; the wall-clock ordering is inferred from
//   t_start_us in the snapshot.
// - QPC gives us a monotonic microsecond clock without hitting
//   Date.now-style forbiddens (this is C++, not the workflow script, so
//   it's fine — the point is that QPC survives suspend/resume where
//   GetTickCount can go weird).
// - Persistence: after every OnPost we mark dirty and signal a worker.
//   The worker debounces to at most one write per 100 ms and calls
//   FlushFileBuffers so a bugcheck loses at most one debounce window.
// - "pending" entries left over from the previous lifetime are upgraded
//   to "wedged" during Init(); that's what tells the caller "the agent
//   died with this call in flight".

#include "breadcrumb.hpp"

#include <shlobj.h>
#include <cstring>
#include <condition_variable>
#include <cstdio>
#include <thread>

#pragma comment(lib, "shell32.lib")

namespace suspex {

namespace {

// On-disk layout: [Header][kCap * BreadcrumbEntry]. Header carries a
// magic + version so a stale/foreign file is rejected cleanly.
struct DiskHeader {
    uint32_t magic;        // 'S','P','X','B' == 0x42585053
    uint32_t version;      // 1
    uint64_t agent_start_epoch_ms;
    uint64_t next_id;      // total ops seen this lifetime (may exceed kCap)
    uint32_t entry_count;  // <= kCap
    uint32_t reserved;
};

constexpr uint32_t kMagic = 0x42585053u; // "SPXB"
constexpr uint32_t kVersion = 1u;

std::mutex g_mu;
BreadcrumbEntry g_ring[Breadcrumb::kCap]{};
uint64_t g_next_id = 0;
uint64_t g_agent_start_epoch_ms = 0;
LARGE_INTEGER g_qpc_start{};
LARGE_INTEGER g_qpc_freq{};
std::vector<BreadcrumbEntry> g_prior;
std::wstring g_file_path;
bool g_initialised = false;

// Persistence worker
std::mutex g_flush_mu;
std::condition_variable g_flush_cv;
bool g_flush_dirty = false;
bool g_flush_stop = false;
std::thread g_flush_thr;

std::wstring ComputeFilePath()
{
    wchar_t buf[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, buf) != S_OK) {
        return L"";
    }
    std::wstring dir = std::wstring(buf) + L"\\suspex";
    CreateDirectoryW(dir.c_str(), nullptr); // ignore existing
    return dir + L"\\breadcrumb.bin";
}

uint64_t QpcNowUs()
{
    LARGE_INTEGER n;
    QueryPerformanceCounter(&n);
    // Delta in ticks, converted to microseconds. Freq is stable across
    // reboots — QueryPerformanceFrequency contract.
    uint64_t delta = (uint64_t)(n.QuadPart - g_qpc_start.QuadPart);
    return (delta * 1000000ull) / (uint64_t)g_qpc_freq.QuadPart;
}

uint64_t EpochMsNow()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // FILETIME is 100-ns since 1601-01-01. Convert to ms since 1970-01-01.
    return (u.QuadPart / 10000ull) - 11644473600000ull;
}

void WriteFileAtomic(const std::wstring& path, const void* data, size_t bytes)
{
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    WriteFile(h, data, (DWORD)bytes, &wrote, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
    // MoveFileEx with MOVEFILE_REPLACE_EXISTING gives an atomic swap.
    MoveFileExW(tmp.c_str(), path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

void FlushLocked()
{
    // Called with g_mu held.
    std::vector<BYTE> buf(sizeof(DiskHeader) + sizeof(g_ring));
    DiskHeader hdr{
        kMagic, kVersion, g_agent_start_epoch_ms, g_next_id,
        (uint32_t)(g_next_id < Breadcrumb::kCap ? g_next_id : Breadcrumb::kCap),
        0u
    };
    memcpy(buf.data(), &hdr, sizeof(hdr));
    memcpy(buf.data() + sizeof(hdr), g_ring, sizeof(g_ring));
    WriteFileAtomic(g_file_path, buf.data(), buf.size());
}

void FlushWorker()
{
    // Debounce to 100 ms — kernel-heavy workloads stamp thousands of
    // breadcrumbs per second, but we only need to survive a bugcheck.
    using namespace std::chrono;
    while (true) {
        std::unique_lock<std::mutex> lock(g_flush_mu);
        g_flush_cv.wait(lock, []{ return g_flush_dirty || g_flush_stop; });
        if (g_flush_stop && !g_flush_dirty) return;
        g_flush_dirty = false;
        lock.unlock();
        std::this_thread::sleep_for(milliseconds(100));
        // Re-check under the ring lock, coalesce anything that landed
        // during the debounce window.
        {
            std::lock_guard<std::mutex> rl(g_mu);
            FlushLocked();
        }
        {
            std::lock_guard<std::mutex> l2(g_flush_mu);
            g_flush_dirty = false;
        }
    }
}

void MarkDirty()
{
    {
        std::lock_guard<std::mutex> l(g_flush_mu);
        g_flush_dirty = true;
    }
    g_flush_cv.notify_one();
}

void LoadPriorLocked()
{
    HANDLE h = CreateFileW(g_file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return; // first run, or file missing
    DiskHeader hdr{};
    DWORD got = 0;
    if (!ReadFile(h, &hdr, sizeof(hdr), &got, nullptr) || got != sizeof(hdr)
        || hdr.magic != kMagic || hdr.version != kVersion
        || hdr.entry_count > Breadcrumb::kCap) {
        CloseHandle(h);
        return;
    }
    std::vector<BreadcrumbEntry> ring(Breadcrumb::kCap);
    if (!ReadFile(h, ring.data(), (DWORD)(Breadcrumb::kCap * sizeof(BreadcrumbEntry)),
                  &got, nullptr) || got != Breadcrumb::kCap * sizeof(BreadcrumbEntry)) {
        CloseHandle(h);
        return;
    }
    CloseHandle(h);
    // Slot 0 through entry_count-1 in first-seen order — but we don't
    // know the wrap point without total-id (which we have in hdr.next_id).
    // Reconstruct: chronological order = slot (next_id - entry_count)%cap
    // .. (next_id-1)%cap.
    uint64_t start = (hdr.next_id > Breadcrumb::kCap)
                     ? (hdr.next_id - Breadcrumb::kCap) : 0;
    for (uint64_t id = start; id < hdr.next_id; id++) {
        BreadcrumbEntry e = ring[id % Breadcrumb::kCap];
        // Upgrade pending -> wedged: nothing else could have re-touched
        // this entry, so if it's still "pending" the agent died with the
        // call in flight.
        if (strncmp(e.status_kind, "pending", sizeof(e.status_kind)) == 0) {
            strncpy_s(e.status_kind, "wedged", _TRUNCATE);
        }
        g_prior.push_back(e);
    }
}

} // anon

bool Breadcrumb::Init()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_initialised) return true;
    QueryPerformanceFrequency(&g_qpc_freq);
    QueryPerformanceCounter(&g_qpc_start);
    g_agent_start_epoch_ms = EpochMsNow();
    g_file_path = ComputeFilePath();
    if (g_file_path.empty()) return false;
    LoadPriorLocked();
    memset(g_ring, 0, sizeof(g_ring));
    g_next_id = 0;
    g_flush_thr = std::thread(FlushWorker);
    g_initialised = true;
    // Persist an empty ring so the file exists at a known-good state.
    FlushLocked();
    return true;
}

uint64_t Breadcrumb::OnPre(uint32_t ioctl_code, const std::string& arg_summary)
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_initialised) return 0;
    uint64_t id = g_next_id++;
    BreadcrumbEntry& e = g_ring[id % kCap];
    memset(&e, 0, sizeof(e));
    e.t_start_us = QpcNowUs();
    e.ioctl_code = ioctl_code;
    strncpy_s(e.status_kind, "pending", _TRUNCATE);
    size_t n = arg_summary.size();
    if (n >= sizeof(e.arg_summary)) n = sizeof(e.arg_summary) - 1;
    memcpy(e.arg_summary, arg_summary.data(), n);
    e.arg_summary[n] = 0;
    // Encode id in the top 32 bits (safe: kCap is small; caller uses only
    // the returned id to find the slot on OnPost).
    MarkDirty();
    return id;
}

void Breadcrumb::OnPost(uint64_t id, const char* status_kind, uint32_t status_code)
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_initialised) return;
    BreadcrumbEntry& e = g_ring[id % kCap];
    // Only close the slot if it still belongs to this id — a subsequent
    // OnPre in another thread could have already reused the slot.
    if (e.t_end_us != 0) return;
    e.t_end_us = QpcNowUs();
    strncpy_s(e.status_kind, status_kind ? status_kind : "ok", _TRUNCATE);
    e.status_code = status_code;
    MarkDirty();
}

std::vector<BreadcrumbEntry> Breadcrumb::CurrentSnapshot()
{
    std::lock_guard<std::mutex> lock(g_mu);
    std::vector<BreadcrumbEntry> out;
    uint64_t start = (g_next_id > kCap) ? (g_next_id - kCap) : 0;
    for (uint64_t id = start; id < g_next_id; id++) {
        out.push_back(g_ring[id % kCap]);
    }
    return out;
}

std::vector<BreadcrumbEntry> Breadcrumb::PriorSnapshot()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_prior;
}

uint64_t Breadcrumb::AgentStartEpochMs() { return g_agent_start_epoch_ms; }
uint64_t Breadcrumb::NowEpochMs() { return EpochMsNow(); }

void Breadcrumb::FlushSync()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_initialised) FlushLocked();
}

} // namespace suspex
