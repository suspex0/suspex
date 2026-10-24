#pragma once

// v1.0.1 Phase 5 — listener self-test.
//
// Rig field report: agent process alive, netstat shows 0.0.0.0:50074
// LISTENING (same PID), but all new TCP SYNs — loopback included — time
// out while SMB on the same interfaces answers. The accept path stopped
// draining; only taskkill + restart recovered it. This watcher makes the
// agent notice and heal itself: a raw loopback TCP connect every N
// seconds, and after K consecutive dead probes the caller's on_wedge()
// fires (expected use: server->Shutdown() so the main loop rebuilds the
// listener — fresh socket, fresh connection set, dead clients reaped).
//
// Deliberately standalone: no agent headers, also linked into umagent.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace suspex::listenwatch {

// One TCP connect attempt to addr:port. True when the listener accepts
// within timeout_ms. This is a raw socket probe, NOT a gRPC call: the
// observed failure mode leaves the port LISTENING while SYNs time out,
// so anything above TCP cannot be trusted as a health signal. Returns
// true (assume-alive) when winsock cannot initialize — a broken probe
// must never trigger a rebuild loop.
bool LoopbackProbe(uint16_t port, int timeout_ms);

// v1.0.1.1: the rig wedge also manifested as LAN-only SYN drops (SMB on
// the same interfaces answered; loopback passed). A loopback-only probe
// is blind to that, so the watch probes 127.0.0.1 AND every up-adapter
// IPv4 (re-enumerated each cycle — DHCP moves them). A strike is any
// probe that times out; media-disconnected adapters are skipped.
bool PortReachable(uint16_t port, int timeout_ms, std::string* failHint);

// Polls 127.0.0.1:port every interval_s; after fail_threshold
// consecutive dead probes invokes on_wedge() once per wedge episode (on
// the watch thread; must not block for long). Recovery is logged only.
class Watch {
public:
    Watch(uint16_t port, std::function<void()> on_wedge, int interval_s = 15,
          int fail_threshold = 3);
    ~Watch(); // Stop()
    void Stop();

private:
    void Run();

    uint16_t port_;
    std::function<void()> on_wedge_;
    int interval_s_;
    int fail_threshold_;
    std::atomic<bool> stop_{false};
    std::thread th_;
};

} // namespace suspex::listenwatch
