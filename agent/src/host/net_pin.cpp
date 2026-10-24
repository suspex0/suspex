// v1.0.1 Phase 2.2 — static-IPv4 pin manager.

#include "net_pin.hpp"

// winsock2.h MUST come before windows.h (see host_info.cpp for the same
// ordering note); iphlpapi.h/netioapi.h pull the adapter + address-row
// types and need winsock2's structs first.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace suspex::host {

namespace {

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(),
                                nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(),
                        w.data(), n);
    return w;
}

uint64_t NowEpochMs()
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

bool HoldMarkerSet(const AgentConfig& cfg)
{
    if (GetEnvironmentVariableW(L"SUSPEX_NET_PIN_HOLD", nullptr, 0) > 0) {
        return true;
    }
    const std::wstring& path = cfg.pinHoldMarker;
    if (!path.empty() && GetFileAttributesW(path.c_str()) !=
            INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    // Fallback marker file path when the caller didn't configure one.
    wchar_t tmp[MAX_PATH]{};
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n > 0) {
        std::wstring fallback(tmp, n);
        fallback += L"suspex_net_pin_hold";
        if (GetFileAttributesW(fallback.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}

bool FindAdapterByFriendly(const std::wstring& friendly, NET_LUID* luidOut,
                           std::string* currentIpv4)
{
    ULONG size = 15 * 1024;
    std::vector<unsigned char> buf(size);
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    DWORD rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                    (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    }
    if (rc != NO_ERROR) return false;
    for (auto* ad = (IP_ADAPTER_ADDRESSES*)buf.data(); ad != nullptr;
         ad = ad->Next) {
        if (friendly.compare(ad->FriendlyName) != 0) continue;
        *luidOut = ad->Luid;
        if (currentIpv4 != nullptr) {
            for (auto* u = ad->FirstUnicastAddress; u != nullptr;
                 u = u->Next) {
                if (u->Address.lpSockaddr != nullptr &&
                    u->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET,
                              &((sockaddr_in*)u->Address.lpSockaddr)
                                  ->sin_addr,
                              ip, sizeof(ip));
                    *currentIpv4 = ip;
                    break;
                }
            }
        }
        return true;
    }
    return false;
}

// Apply pin_address/pin_prefix to the adapter identified by LUID.
// Falls back to netsh when the API path fails; the netsh cmdline is
// logged into `*log` for forensics.
bool PinStatic(const NET_LUID& luid, const std::string& address,
               uint32_t prefix, const std::string& gateway,
               std::string* err)
{
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    if (inet_pton(AF_INET, address.c_str(), &sin.sin_addr) != 1) {
        if (err) *err = "pin_address not a valid IPv4: " + address;
        return false;
    }
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address.Ipv4 = sin;
    row.OnLinkPrefixLength = (UINT8)prefix;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.ValidLifetime = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.SkipAsSource = FALSE;
    DWORD rc = CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        if (err) {
            *err = "CreateUnicastIpAddressEntry rc=" + std::to_string(rc);
        }
        return false;
    }
    if (!gateway.empty()) {
        sockaddr_in gw{};
        gw.sin_family = AF_INET;
        if (inet_pton(AF_INET, gateway.c_str(), &gw.sin_addr) == 1) {
            MIB_IPFORWARD_ROW2 fwd{};
            InitializeIpForwardEntry(&fwd);
            fwd.InterfaceLuid = luid;
            // 0.0.0.0/0 default route via gw.
            fwd.DestinationPrefix.Prefix.si_family = AF_INET;
            fwd.DestinationPrefix.PrefixLength = 0;
            fwd.NextHop.si_family = AF_INET;
            fwd.NextHop.Ipv4 = gw;
            fwd.Metric = 25;
            DWORD rc2 = CreateIpForwardEntry2(&fwd);
            (void)rc2; // best-effort; don't fail pin on gateway errors
        }
    }
    return true;
}

} // namespace

struct NetPinMgr::Impl {
    HANDLE change_notify = nullptr;
    std::atomic<bool> running{false};
    std::thread debounce_thread;
    std::atomic<uint64_t> last_change_at_ms{0};
    std::mutex m;
    NetPinState state;
};

NetPinMgr::NetPinMgr(const AgentConfig& cfg)
    : cfg_(cfg), impl_(std::make_unique<Impl>())
{
    impl_->state.enabled = !cfg_.pinAdapter.empty() &&
                           !cfg_.pinAddress.empty();
    impl_->state.adapter = WideToUtf8(cfg_.pinAdapter);
    impl_->state.pinned_address = WideToUtf8(cfg_.pinAddress);
    impl_->state.pinned_prefix = cfg_.pinPrefix;
    impl_->state.pinned_gateway = WideToUtf8(cfg_.pinGateway);
}

NetPinMgr::~NetPinMgr()
{
    Stop();
}

static VOID WINAPI OnIpChange(PVOID ctx, PMIB_UNICASTIPADDRESS_ROW,
                              MIB_NOTIFICATION_TYPE)
{
    auto* self = static_cast<NetPinMgr::Impl*>(ctx);
    if (!self) return;
    self->last_change_at_ms.store(NowEpochMs());
}

void NetPinMgr::Start()
{
    if (!impl_->state.enabled) return;
    // Boot-time apply.
    std::string err;
    (void)ApplyOnce(/*clearHold=*/false, &err);

    if (cfg_.pinAtBootOnly) return;

    NotifyUnicastIpAddressChange(AF_INET, OnIpChange, impl_.get(), FALSE,
                                 &impl_->change_notify);
    impl_->running.store(true);
    impl_->debounce_thread = std::thread([this] {
        while (impl_->running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            uint64_t last = impl_->last_change_at_ms.exchange(0);
            if (!last) continue;
            uint64_t debounce = cfg_.pinDebounceMs ? cfg_.pinDebounceMs : 5000;
            // Wait until the quiet window elapses.
            while (impl_->running.load()) {
                uint64_t now = NowEpochMs();
                uint64_t latest = impl_->last_change_at_ms.load();
                if (latest > last) last = latest;
                if (now - last >= debounce) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            std::string e;
            (void)ApplyOnce(/*clearHold=*/false, &e);
        }
    });
}

void NetPinMgr::Stop()
{
    if (impl_->change_notify) {
        CancelMibChangeNotify2(impl_->change_notify);
        impl_->change_notify = nullptr;
    }
    impl_->running.store(false);
    if (impl_->debounce_thread.joinable()) {
        impl_->debounce_thread.join();
    }
}

bool NetPinMgr::ApplyOnce(bool clearHold, std::string* errOut)
{
    std::lock_guard<std::mutex> lk(impl_->m);
    if (!impl_->state.enabled) {
        if (errOut) *errOut = "pin disabled";
        return false;
    }
    bool hold = HoldMarkerSet(cfg_);
    if (hold && !clearHold) {
        impl_->state.hold = true;
        if (errOut) *errOut = "hold marker set — pin skipped";
        return false;
    }
    impl_->state.hold = false;
    NET_LUID luid{};
    std::string current_ipv4;
    if (!FindAdapterByFriendly(cfg_.pinAdapter, &luid, &current_ipv4)) {
        impl_->state.last_error =
            "adapter not found: " + WideToUtf8(cfg_.pinAdapter);
        impl_->state.pin_failures_streak++;
        if (errOut) *errOut = impl_->state.last_error;
        return false;
    }
    impl_->state.current_address = current_ipv4;
    if (current_ipv4 == impl_->state.pinned_address) {
        // Already correct — nothing to do.
        impl_->state.last_pin_at_epoch_ms = NowEpochMs();
        impl_->state.pin_failures_streak = 0;
        impl_->state.last_error.clear();
        return true;
    }
    std::string err;
    bool ok = PinStatic(luid, impl_->state.pinned_address,
                        impl_->state.pinned_prefix,
                        impl_->state.pinned_gateway, &err);
    impl_->state.pin_attempts++;
    impl_->state.last_pin_at_epoch_ms = NowEpochMs();
    if (!ok) {
        impl_->state.pin_failures_streak++;
        impl_->state.last_error = err;
        if (errOut) *errOut = err;
        return false;
    }
    impl_->state.pin_failures_streak = 0;
    impl_->state.last_error.clear();
    return true;
}

NetPinState NetPinMgr::Snapshot() const
{
    std::lock_guard<std::mutex> lk(impl_->m);
    return impl_->state;
}

} // namespace suspex::host
