#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

namespace suspex {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

// raw dbgeng command passthrough: captures engine output through an
// IDebugOutputCallbacksWide sink while the command executes
class DbgOutputSink : public IDebugOutputCallbacksWide {
public:
    STDMETHODIMP QueryInterface(REFIID riid, PVOID* obj) override
    {
        if (!obj) {
            return E_INVALIDARG;
        }
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDebugOutputCallbacksWide)) {
            *obj = this;
            AddRef();
            return S_OK;
        }
        *obj = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    STDMETHODIMP_(ULONG) Release() override { return InterlockedDecrement(&refs_); }
    STDMETHODIMP Output(ULONG mask, PCWSTR text) override
    {
        UNREFERENCED_PARAMETER(mask);
        std::lock_guard<std::mutex> lk(bufM_);
        if (text) {
            buf_ += text;
            if (buf_.size() > 4 * 1024 * 1024) { // 8MB of UTF-16 max
                buf_.resize(4 * 1024 * 1024);
            }
        }
        return S_OK;
    }
    std::wstring Take()
    {
        std::lock_guard<std::mutex> lk(bufM_);
        return std::move(buf_);
    }

private:
    LONG refs_ = 1;
    std::mutex bufM_;
    std::wstring buf_;
};

std::string DbgSession::Execute(const std::string& command, std::string* output)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    // v0.9.4: dbgeng's IDebugControl::Execute() silently accepts commands
    // while the target is running but produces no output through the
    // registered callbacks — the caller sees ok=true with an empty
    // buffer and no way to tell the command actually ran or was
    // discarded. Reject the call explicitly so the caller knows to
    // break first (or Continue only when done with commands).
    auto client = As<IDebugClient5>(&client5_);
    auto control = As<IDebugControl3>(&control3_);
    bool interruptedForCmd = false;
    if (!stopped_) {
        if (!monitor_) {
            return "target is running (dbgeng discards output on running "
                   "targets; break the target first or issue commands "
                   "between stops)";
        }
        // monitor mode: the debugee runs continuously, so commands that
        // need a stopped state (ba, etc.) do an interrupt → cmd → resume
        // cycle — passive observation must never park the target.
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
        interruptedForCmd = true;
    }
    if (command.empty()) {
        return "empty command";
    }
    // IDebugControl3::Execute takes an ANSI command string
    std::string narrow = command;

    static DbgOutputSink sink; // shared: only one command executes at a time (m_)
    sink.Take(); // clear previous output
    if (FAILED(client->SetOutputCallbacksWide(&sink))) {
        return "SetOutputCallbacksWide failed";
    }
    HRESULT hr = control->Execute(DEBUG_EXECUTE_NOT_LOGGED, narrow.c_str(), 0);
    client->SetOutputCallbacksWide(nullptr); // restore before touching sink
    if (FAILED(hr)) {
        return "Execute failed hr=" + std::to_string(hr);
    }
    std::wstring out = sink.Take();
    int n = WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), nullptr, 0, nullptr, nullptr);
    output->assign(n ? n : 0, '\0');
    if (n) {
        WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), output->data(), n, nullptr, nullptr);
    }
    if (interruptedForCmd) {
        ResumeAfterInterrupt(); // resume the target we broke for the command
    }
    return "";
    });
}

} // namespace suspex
