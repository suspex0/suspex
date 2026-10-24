#include "listen_watch.hpp"
#include "srv_log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <climits>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace suspex::listenwatch {

bool LoopbackProbe(uint16_t port, int timeout_ms)
{
    static const bool wsa_ok = [] {
        WSADATA d{};
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    static bool wsa_fail_logged = false;
    if (!wsa_ok) {
        if (!wsa_fail_logged) {
            srvlog::Logf("listener self-test: WSAStartup failed — probing disabled");
            wsa_fail_logged = true;
        }
        return true; // cannot test: never trigger a rebind off our own bug
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(s, (sockaddr*)&sa, sizeof(sa)); // async: WSAEWOULDBLOCK expected

    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    bool ok = false;
    int ready = select(0, nullptr, &wr, nullptr, &tv);
    if (ready > 0 && FD_ISSET(s, &wr)) {
        int err = 0;
        int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        ok = (err == 0);
    }
    closesocket(s);
    return ok;
}

static bool ConnectProbe(uint32_t ipNet, uint16_t port, int timeout_ms)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ipNet;
    connect(s, (sockaddr*)&sa, sizeof(sa));
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    bool ok = false;
    if (select(0, nullptr, &wr, nullptr, &tv) > 0 && FD_ISSET(s, &wr)) {
        int err = 0;
        int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        ok = (err == 0);
    }
    closesocket(s);
    return ok;
}

bool PortReachable(uint16_t port, int timeout_ms, std::string* failHint)
{
    if (!LoopbackProbe(port, timeout_ms)) {
        if (failHint) *failHint = "127.0.0.1";
        return false;
    }
    // Every up-adapter IPv4, fresh each cycle (DHCP moves them).
    ULONG size = 15 * 1024;
    std::vector<unsigned char> buf(size);
    DWORD rc = GetAdaptersAddresses(AF_INET, 0, nullptr,
                                    (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, 0, nullptr,
                                  (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    }
    if (rc != NO_ERROR) {
        return true; // cannot enumerate: loopback pass is the best we have
    }
    int probed = 0;
    char ip[INET_ADDRSTRLEN] = {};
    for (auto* ad = (IP_ADAPTER_ADDRESSES*)buf.data(); ad != nullptr;
         ad = ad->Next) {
        if (ad->OperStatus != IfOperStatusUp) continue;
        for (auto* u = ad->FirstUnicastAddress; u != nullptr; u = u->Next) {
            if (u->Address.lpSockaddr == nullptr ||
                u->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            uint32_t ipNet = ((sockaddr_in*)u->Address.lpSockaddr)->sin_addr.s_addr;
            if (ipNet == htonl(INADDR_LOOPBACK)) continue;
            probed++;
            if (!ConnectProbe(ipNet, port, timeout_ms)) {
                if (failHint) {
                    inet_ntop(AF_INET, &ipNet, ip, sizeof(ip));
                    *failHint = ip;
                }
                return false;
            }
        }
        if (probed >= 4) break; // cap: enough coverage, bounded probe time
    }
    return true;
}

Watch::Watch(uint16_t port, std::function<void()> on_wedge, int interval_s,
             int fail_threshold)
    : port_(port), on_wedge_(std::move(on_wedge)),
      interval_s_(interval_s > 0 ? interval_s : 15),
      fail_threshold_(fail_threshold > 0 ? fail_threshold : 3)
{
    th_ = std::thread([this] { Run(); });
}

Watch::~Watch()
{
    Stop();
}

void Watch::Stop()
{
    stop_.store(true);
    if (th_.joinable()) {
        th_.join();
    }
}

void Watch::Run()
{
    srvlog::Logf("listener self-test active: 127.0.0.1 + adapter IPs port %u every %ds (%d strikes)",
                 (unsigned)port_, interval_s_, fail_threshold_);
    int streak = 0;
    bool wedged = false;
    while (!stop_.load()) {
        std::string failHint;
        if (PortReachable(port_, 3000, &failHint)) {
            if (wedged) {
                srvlog::Logf("listener self-test on port %u recovered", (unsigned)port_);
                wedged = false;
            }
            streak = 0;
        } else {
            streak++;
            if (streak >= fail_threshold_) {
                if (!wedged) {
                    wedged = true;
                    srvlog::Logf("listener self-test FAILED %dx on port %u (last dead target: %s) — requesting rebind",
                                 streak, (unsigned)port_, failHint.c_str());
                    if (on_wedge_) {
                        try {
                            on_wedge_();
                        } catch (...) {
                        }
                    }
                }
            } else {
                srvlog::Logf("listener self-test miss %d/%d on port %u (target %s)", streak,
                             fail_threshold_, (unsigned)port_, failHint.c_str());
            }
        }
        // Sleep in short slices so Stop() stays responsive.
        for (int i = 0; i < interval_s_ * 4 && !stop_.load(); i++) {
            Sleep(250);
        }
    }
}

} // namespace suspex::listenwatch
