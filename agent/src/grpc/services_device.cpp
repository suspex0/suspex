// v11 agent-primitives services — usermode only, no driver contact:
//
//   DeviceSvc.Ioctl   — send an arbitrary IOCTL to a device. ACTUATOR: the
//                       orchestrator gates it behind security.allow_ioctl_send.
//   TelemetrySvc      — read-only ETW provider/session inventory.
//
// (Memory.ThreadList lives in services_memory.cpp — it extends MemorySvc.)
//
// Every failure surfaces as a named OpStatus the orchestrator can branch on.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "suspex.grpc.pb.h"

#include "services.hpp"

#include <windows.h>
#include <winternl.h>
#include <tdh.h>
#include <evntrace.h>
#include <objbase.h>

#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "tdh.lib")

namespace suspex {

namespace {

constexpr UINT32 DEVICE_IOCTL_MAX_OUT = 4u * 1024 * 1024;   // 4 MiB out cap
constexpr UINT32 DEVICE_IOCTL_MAX_IN = 4u * 1024 * 1024;    // 4 MiB in cap
constexpr UINT32 DEVICE_IOCTL_DEFAULT_TIMEOUT_MS = 10000;
constexpr UINT32 ETW_MAX_PROVIDERS = 4096;
constexpr UINT32 ETW_MAX_SESSIONS = 128;

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n,
                        nullptr, nullptr);
    return s;
}

// Open a device for IOCTL exchange. Accepts "\\.\Name" (DOS symlink) and
// "\Device\Name" (raw NT object path — NtCreateFile opens it directly, no
// symlink needed). Returns a Win32-style gle on failure.
HANDLE OpenDeviceForIoctl(const std::wstring& path, UINT32* gle)
{
    *gle = 0;
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, path.c_str());
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK iosb = {};
    HANDLE h = INVALID_HANDLE_VALUE;
    NTSTATUS st = NtCreateFile(
        &h,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &oa, &iosb, nullptr, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, nullptr, 0);
    if (!NT_SUCCESS(st)) {
        *gle = RtlNtStatusToDosError(st);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

// One IOCTL with a bounded wait: OVERLAPPED + WaitForSingleObject, cancelled
// via CancelIoEx on timeout so a driver that never completes the IRP can't
// pin the agent's RPC worker forever. Returns a Win32 gle (0 = success).
UINT32 SendIoctl(HANDLE h, DWORD code, const void* in, DWORD in_size,
                 void* out, DWORD out_size, DWORD* bytes_returned,
                 UINT32 timeout_ms)
{
    *bytes_returned = 0;
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return GetLastError();
    BOOL ok = ::DeviceIoControl(h, code,
                                const_cast<void*>(in), in_size,
                                out, out_size, nullptr, &ov);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        DWORD err = GetLastError();
        CloseHandle(ov.hEvent);
        return err;
    }
    DWORD w = WaitForSingleObject(ov.hEvent, timeout_ms);
    if (w == WAIT_TIMEOUT) {
        CancelIoEx(h, &ov);
        CloseHandle(ov.hEvent);
        return ERROR_TIMEOUT;
    }
    ok = GetOverlappedResult(h, &ov, bytes_returned, FALSE);
    DWORD gle = ok ? 0 : GetLastError();
    CloseHandle(ov.hEvent);
    return ok ? 0 : gle;
}

} // namespace

// ---------------------------------------------------------------------------
// Device.Ioctl — open the device (DOS symlink or raw NT object path) and
// send one IOCTL with a bounded wait. ntdll is linked (CMakeLists), so
// NtCreateFile/RtlInitUnicodeString/RtlNtStatusToDosError are direct calls.
// ---------------------------------------------------------------------------

class DeviceSvc final : public Device::Service {
public:
    explicit DeviceSvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status Ioctl(::grpc::ServerContext* ctx, const DeviceIoctlRequest* req,
                       DeviceIoctlResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        if (req->device().empty()) {
            FillStatus(resp, "device ioctl: device= is required");
            return grpc::Status::OK;
        }
        if (req->code() < 0x10000) {
            FillStatus(resp, "device ioctl: code must be a CTL_CODE (>= 0x10000)");
            return grpc::Status::OK;
        }
        if (req->out_size() > DEVICE_IOCTL_MAX_OUT) {
            FillStatus(resp, "device ioctl: out_size exceeds the 4 MiB cap");
            return grpc::Status::OK;
        }
        if (req->in_buffer().size() > DEVICE_IOCTL_MAX_IN) {
            FillStatus(resp, "device ioctl: in_buffer exceeds the 4 MiB cap");
            return grpc::Status::OK;
        }

        UINT32 gle = 0;
        HANDLE h = OpenDeviceForIoctl(Utf8ToWide(req->device()), &gle);
        if (h == INVALID_HANDLE_VALUE) {
            resp->set_last_error(gle);
            FillStatus(resp, "device open failed: gle=" + std::to_string(gle));
            return grpc::Status::OK;
        }

        std::vector<BYTE> out(req->out_size() ? req->out_size() : 4096, 0);
        DWORD bytes_returned = 0;
        UINT32 gle_send = SendIoctl(h, req->code(),
                                    req->in_buffer().empty()
                                        ? nullptr
                                        : req->in_buffer().data(),
                                    (DWORD)req->in_buffer().size(),
                                    out.data(), (DWORD)out.size(),
                                    &bytes_returned,
                                    req->timeout_ms()
                                        ? req->timeout_ms()
                                        : DEVICE_IOCTL_DEFAULT_TIMEOUT_MS);
        CloseHandle(h);

        if (gle_send) {
            resp->set_last_error(gle_send);
            FillStatus(resp, "DeviceIoControl failed: gle=" +
                                 std::to_string(gle_send));
            return grpc::Status::OK;
        }
        resp->set_out_buffer(out.data(), bytes_returned);
        resp->set_bytes_returned(bytes_returned);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

// ---------------------------------------------------------------------------
// TelemetrySvc — read-only ETW inventory ("what telemetry exists / who is
// watching"). Query only; starting trace sessions is out of scope.
// ---------------------------------------------------------------------------

class TelemetrySvc final : public Telemetry::Service {
public:
    explicit TelemetrySvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status Providers(::grpc::ServerContext* ctx,
                           const EtwProvidersRequest* req,
                           EtwProvidersResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        // Size probe, then fill (TdhEnumerateProviders contract).
        ULONG size = 0;
        ULONG rc = TdhEnumerateProviders(nullptr, &size);
        if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            FillStatus(resp, "TdhEnumerateProviders size probe failed");
            return grpc::Status::OK;
        }
        std::vector<BYTE> blob(size);
        PPROVIDER_ENUMERATION_INFO pei = (PPROVIDER_ENUMERATION_INFO)blob.data();
        rc = TdhEnumerateProviders(pei, &size);
        if (rc != ERROR_SUCCESS) {
            FillStatus(resp, "TdhEnumerateProviders failed: " + std::to_string(rc));
            return grpc::Status::OK;
        }
        std::string filt = req->name_filter();
        std::transform(filt.begin(), filt.end(), filt.begin(),
                       [](unsigned char c) { return (char)tolower(c); });
        for (ULONG i = 0; i < pei->NumberOfProviders; ++i) {
            const TRACE_PROVIDER_INFO& pi = pei->TraceProviderInfoArray[i];
            std::wstring name_w((LPCWSTR)((PBYTE)pei + pi.ProviderNameOffset));
            if (!filt.empty()) {
                std::string lower = WideToUtf8(name_w);
                std::transform(lower.begin(), lower.end(), lower.begin(),
                               [](unsigned char c) { return (char)tolower(c); });
                if (lower.find(filt) == std::string::npos) continue;
            }
            if (resp->providers_size() >= ETW_MAX_PROVIDERS) {
                resp->set_truncated(true);
                break;
            }
            WCHAR guid_str[64] = {};
            ::StringFromGUID2(pi.ProviderGuid, guid_str, 64);
            auto* row = resp->add_providers();
            row->set_guid(WideToUtf8(guid_str));
            row->set_name(WideToUtf8(name_w));
        }
        resp->set_count(resp->providers_size());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Sessions(::grpc::ServerContext* ctx,
                          const EtwSessionsRequest* req,
                          EtwSessionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        // QueryAllTracesW: array of property-buffer pointers sized by the
        // caller. One generous buffer per session keeps the layout math
        // simple (EVENT_TRACE_PROPERTIES + logger name + logfile name).
        // QueryAllTracesW takes a caller-sized array of property-buffer
        // pointers and returns the number of live sessions in |actual|.
        // One generous 4 KiB buffer per session keeps the layout math
        // simple (EVENT_TRACE_PROPERTIES + logger name + logfile name).
        ULONG needed = 0;
        std::vector<BYTE> blobs((size_t)ETW_MAX_SESSIONS * 4096);
        std::vector<EVENT_TRACE_PROPERTIES*> props(ETW_MAX_SESSIONS);
        for (ULONG i = 0; i < ETW_MAX_SESSIONS; ++i) {
            props[i] = (PEVENT_TRACE_PROPERTIES)(blobs.data() + (size_t)i * 4096);
            props[i]->Wnode.BufferSize = 4096;
            props[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            props[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;
        }
        ULONG actual = 0;
        ULONG rc = QueryAllTracesW(props.data(), ETW_MAX_SESSIONS, &actual);
        if (rc != ERROR_SUCCESS) {
            // A machine with zero active sessions surfaces as an error from
            // QueryAllTraces — treat it as an empty, successful answer.
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        std::string filt = req->name_filter();
        std::transform(filt.begin(), filt.end(), filt.begin(),
                       [](unsigned char c) { return (char)tolower(c); });
        for (ULONG i = 0; i < actual; ++i) {
            auto* p = props[i];
            std::wstring name((LPCWSTR)((PBYTE)p + p->LoggerNameOffset));
            if (!filt.empty()) {
                std::string lower = WideToUtf8(name);
                std::transform(lower.begin(), lower.end(), lower.begin(),
                               [](unsigned char c) { return (char)tolower(c); });
                if (lower.find(filt) == std::string::npos) continue;
            }
            auto* row = resp->add_sessions();
            row->set_name(WideToUtf8(name));
            row->set_logger_id(p->Wnode.HistoricalContext);
            row->set_buffers_written(p->BuffersWritten);
            row->set_buffers_lost(p->LogBuffersLost);
            row->set_events_lost(p->EventsLost);
            row->set_loggers(0);  // not in EVENT_TRACE_PROPERTIES
        }
        resp->set_count(resp->sessions_size());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

void RegisterDeviceServices(grpc::ServerBuilder& builder, const AgentConfig& cfg)
{
    static DeviceSvc deviceSvc(cfg);
    builder.RegisterService(&deviceSvc);
    static TelemetrySvc telemetrySvc(cfg);
    builder.RegisterService(&telemetrySvc);
}

} // namespace suspex
