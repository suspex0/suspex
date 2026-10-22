// suspex_comm core: device handle lifecycle, IOCTL dispatch, trace hooks,
// and the trivial Ping wrapper. Split from suspex_comm.cpp (Phase 7c).
#include "suspex_comm_internal.hpp"

#include <cstdio>
#include <string>

namespace suspex {

bool Driver::Open()
{
    if (IsOpen()) {
        return true;
    }
    h_ = CreateFileW(L"\\\\.\\SuspexDrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_ == INVALID_HANDLE_VALUE) {
        Fail("CreateFile(\\\\.\\SuspexDrv)", GetLastError());
        return false;
    }
    return true;
}

void Driver::Close()
{
    if (h_ != INVALID_HANDLE_VALUE) {
        CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }
}

ULONG Driver::LastNtStatus()
{
    // ntdll is mapped into every Windows process; fetch RtlGetLastNtStatus
    // lazily so targets that don't link ntdll.lib (mapper, drv_exerciser)
    // build unchanged.
    typedef LONG(NTAPI* RtlGetLastNtStatusFn)();
    static RtlGetLastNtStatusFn fn = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (RtlGetLastNtStatusFn)GetProcAddress(
            ntdll, "RtlGetLastNtStatus") : (RtlGetLastNtStatusFn) nullptr;
    }();
    return fn ? (ULONG)fn() : 0;
}

void Driver::Fail(const char* what, DWORD gle)
{
    char buf[64];
    sprintf_s(buf, " gle=%lu", (unsigned long)gle);
    lastError_ = std::string(what) + buf;
    // The Win32 projection flattens the driver's NTSTATUS (e.g.
    // STATUS_UNEXPECTED_IO_ERROR -> gle=59). Appending the raw code keeps
    // the orchestrator's classifier pointed at the real fault class
    // instead of the generic driver-error bucket. Best-effort: a failure
    // that never reached an NT syscall leaves a stale/zero value — the
    // zero case is skipped here; a stale value still reads harmlessly.
    ULONG nt = LastNtStatus();
    if (nt != 0) {
        sprintf_s(buf, " nt=0x%08lx", nt);
        lastError_ += buf;
    }
}

bool Driver::FailNt(const char* what, UINT32 nt)
{
    char buf[64];
    sprintf_s(buf, " nt=0x%08x", nt);
    lastError_ = std::string(what) + buf;
    return false;
}

// v5: process-wide trace hooks. Set once at agent startup; drv_exerciser
// leaves them null so it doesn't pollute the agent's breadcrumb file.
static TracePreFn g_trace_pre = nullptr;
static TracePostFn g_trace_post = nullptr;

void Driver::SetTraceHooks(TracePreFn pre, TracePostFn post)
{
    g_trace_pre = pre;
    g_trace_post = post;
}

bool Driver::Call(ULONG ioctl, void* in, ULONG inSize, void* out, ULONG outSize, ULONG* bytesReturned)
{
    if (!IsOpen() && !Open()) {
        return false;
    }
    uint64_t token = 0;
    if (g_trace_pre) {
        token = g_trace_pre(ioctl, in, inSize);
    }
    DWORD ret = 0;
    if (!DeviceIoControl(h_, ioctl, in, inSize, out, outSize, &ret, nullptr)) {
        DWORD gle = GetLastError();
        // The device can vanish under us: the driver service was stopped,
        // swapped (drvswap/update flow) or the VM rolled back. A stale
        // handle keeps IsOpen() true forever, so every subsequent op would
        // fail until the agent restarts. Reopen once on handle/device-loss
        // errors and retry the IOCTL against the fresh handle.
        if (gle == ERROR_INVALID_HANDLE || gle == ERROR_FILE_NOT_FOUND ||
            gle == ERROR_PATH_NOT_FOUND || gle == ERROR_ACCESS_DENIED ||
            gle == ERROR_NOT_READY || gle == 433 /*ERROR_NO_SUCH_DEVICE*/ ||
            gle == 1168 /*ERROR_NOT_FOUND*/) {
            Close();
            if (Open()) {
                if (DeviceIoControl(h_, ioctl, in, inSize, out, outSize, &ret, nullptr)) {
                    if (bytesReturned) {
                        *bytesReturned = ret;
                    }
                    lastError_.clear();
                    if (g_trace_post) g_trace_post(token, true, 0);
                    return true;
                }
                gle = GetLastError();
            } else {
                // Open() already recorded the CreateFile failure in lastError_
                if (g_trace_post) g_trace_post(token, false, GetLastError());
                return false;
            }
        }
        Fail("DeviceIoControl", gle);
        if (g_trace_post) g_trace_post(token, false, gle);
        return false;
    }
    if (bytesReturned) {
        *bytesReturned = ret;
    }
    lastError_.clear();
    if (g_trace_post) g_trace_post(token, true, 0);
    return true;
}

bool Driver::Ping(PingInfo* out)
{
    SUSPEX_PING_OUT p{};
    if (!Call(SUSPEX_IOCTL_PING, nullptr, 0, &p, sizeof(p), nullptr)) {
        return false;
    }
    out->VersionMajor = p.VersionMajor;
    out->VersionMinor = p.VersionMinor;
    out->NtBuild = p.NtBuild;
    out->Flags = p.Flags;
    out->AbiVersion = p.AbiVersion;
    // v12: cache for MemWrite's legacy-vs-ext header decision. A successful
    // ping is the only trustworthy answer to "which wire shape does the
    // driver parse" — anything else risks the ext tail landing as payload.
    abiVersion_ = p.AbiVersion;
    return true;
}

ULONG IoctlFor(Space s, ULONG user, ULONG kernel, ULONG phys)
{
    switch (s) {
    case Space::Kernel: return kernel;
    case Space::Physical: return phys;
    default: return user;
    }
}

} // namespace suspex
