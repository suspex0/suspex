#pragma once

#include <string>

namespace suspex {

struct AgentConfig {
    int port = 50074;
    std::string token;             // required
    std::wstring driverPath;       // default: <exedir>\suspex_driver.sys
    std::wstring mapperPath;       // default: <exedir>\mapper.exe
    std::wstring trashDir;         // default: <exedir>\.suspex_trash
    bool allowDriverLoad = true;
    bool allowDriverUnload = true;
    bool allowDelete = false;      // hard delete; default move-to-trash
    size_t maxTransferBytes = 512ull * 1024 * 1024;
    size_t maxMemReadBytes = 8ull * 1024 * 1024;

    // v0.31 Phase 5: lifecycle + diagnostics.
    bool devConsole = false;       // --dev: console mode (also disables the
                                   // stdio-to-NUL redirect; see srv_log.hpp)
    std::wstring logPath;          // --log <path>: rotating agent+gRPC log
    size_t logMaxBytes = 4ull * 1024 * 1024; // --log-max-mb <n>

    // v0.31 Phase 2.2: static-IPv4 pinning. Disabled unless pin_adapter
    // is non-empty. The agent re-applies pin_address/pin_prefix (and the
    // optional gateway) at service start and on NotifyUnicastIpAddressChange,
    // debounced by pin_debounce_ms. Only the named adapter is ever touched.
    // The hold-marker env var (SUSPEX_NET_PIN_HOLD) or marker file silences
    // the re-pin for the duration of a deliberate NIC flap.
    std::wstring pinAdapter;
    std::wstring pinAddress;
    uint32_t pinPrefix = 24;
    std::wstring pinGateway;
    uint32_t pinDebounceMs = 5000;
    bool pinAtBootOnly = false;    // skip the change-notification path
    std::wstring pinHoldMarker;    // path checked each pin attempt; set →
                                   // skip. Falls back to %TEMP%\suspex_net_pin_hold.

    static AgentConfig FromArgs(int argc, char** argv);
    static std::wstring ExeDir();
};

} // namespace suspex
