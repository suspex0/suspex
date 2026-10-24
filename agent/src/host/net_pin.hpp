#pragma once

// v1.0.1 Phase 2.2 — static-IPv4 pinning for the agent.
//
// Keeps a named adapter at a configured static IPv4 across reboots and DHCP
// renews. The pin runs at service start and, unless pin_at_boot_only is set,
// re-fires on NotifyUnicastIpAddressChange with a debounce. Only the named
// adapter is touched; a hold marker (env var SUSPEX_NET_PIN_HOLD or a config-
// supplied file path) silences the re-pin for the duration of a deliberate
// NIC flap. Status is reported via NetPinStatusResponse.

#include "../config.hpp"

#include <string>
#include <memory>

namespace suspex::host {

struct NetPinState {
    bool enabled = false;
    bool hold = false;
    std::string adapter;
    std::string pinned_address;
    uint32_t pinned_prefix = 0;
    std::string pinned_gateway;
    std::string current_address;
    uint64_t last_pin_at_epoch_ms = 0;
    uint32_t pin_attempts = 0;
    uint32_t pin_failures_streak = 0;
    std::string last_error;
};

class NetPinMgr {
public:
    explicit NetPinMgr(const AgentConfig& cfg);
    ~NetPinMgr();

    // Start the service (apply + subscribe to IP-address-change if enabled).
    // Safe to call when disabled — becomes a no-op.
    void Start();

    // Stop the change-notification subscription + reset state.
    void Stop();

    // Force a one-shot re-pin now (service RPC path). Returns false and
    // fills `err` on failure. Honors the hold marker unless clearHold is
    // set.
    bool ApplyOnce(bool clearHold, std::string* err);

    // Snapshot for the gRPC Status/HostInfo/NetPinStatus responses.
    NetPinState Snapshot() const;

    // opaque pimpl; definition lives in net_pin.cpp. Public declaration:
    // the NotifyUnicastIpAddressChange callback in the .cpp needs to name
    // it, and the type is never constructible outside that TU anyway.
    struct Impl;

private:
    const AgentConfig& cfg_;
    std::unique_ptr<Impl> impl_;
};

} // namespace suspex::host
