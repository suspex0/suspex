// Desktop display capture via DXGI Desktop Duplication, plus monitor-topology
// JSON for screen_manage(action='displays').
//
// HDR note: the FP16 -> BGRA8 path is a deliberately approximate Reinhard
// tone-map ((half&0x7FFF)/1024 discards exponents); SDR-in-HDR reads slightly
// washed out. A proper half-float decode + SDR-white scale is future work.
#include "screen_common.hpp"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace suspex {
namespace screen {

// Desktop duplication only hands out frames on DWM presents, and an idle
// desktop may not re-compose for minutes. A net-zero mouse jiggle (+1,-1)
// forces one immediately. Runs in the disposable session-1 worker.
static void ForceDesktopPresent()
{
    INPUT inputs[2]{};
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE;
    inputs[0].mi.dx = 1;
    inputs[0].mi.dy = 1;
    inputs[1].type = INPUT_MOUSE;
    inputs[1].mi.dwFlags = MOUSEEVENTF_MOVE;
    inputs[1].mi.dx = -1;
    inputs[1].mi.dy = -1;
    SendInput(2, inputs, sizeof(INPUT));
}

// displayArg: "" (primary), numeric index ("1"), or a DXGI device name
// ("DISPLAY1"). The name match happens against DXGI_OUTPUT_DESC.DeviceName
// during enumeration — the caller never needs to pre-resolve it.
bool CaptureDesktopDxgi(const std::string& displayArg, std::vector<uint8_t>& outPng,
                        uint32_t& outW, uint32_t& outH)
{
    outPng.clear();
    outW = outH = 0;
    ForceDesktopPresent();

    ComPtr<IDXGIFactory1> factory;
    HRESULT hrF = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hrF)) {
        fprintf(stderr, "ddxgi: CreateDXGIFactory1 hr=0x%08lX\n", (unsigned long)hrF);
        return false;
    }

    const bool numeric = displayArg.empty() ||
        displayArg.find_first_not_of("0123456789") == std::string::npos;
    const uint32_t wantIndex =
        numeric ? (uint32_t)atoi(displayArg.c_str()) : 0;
    std::wstring wantName;
    if (!numeric) {
        wantName.assign(displayArg.begin(), displayArg.end());
    }

    ComPtr<IDXGIAdapter1> adapter;
    ComPtr<IDXGIOutput> output;
    ComPtr<ID3D11Device> dev;
    ComPtr<ID3D11DeviceContext> ctx;
    ComPtr<IDXGIOutputDuplication> dup;
    uint32_t cur = 0;

    for (UINT a = 0; factory->EnumAdapters1(a, &adapter) != DXGI_ERROR_NOT_FOUND; ++a) {
        for (UINT o = 0; adapter->EnumOutputs(o, &output) != DXGI_ERROR_NOT_FOUND; ++o) {
            DXGI_OUTPUT_DESC od{};
            output->GetDesc(&od);
            if (!od.AttachedToDesktop) {
                output.Reset();
                continue;
            }
            bool match = numeric
                ? (cur == wantIndex)
                : (!wantName.empty() &&
                   _wcsnicmp(od.DeviceName, wantName.c_str(), wantName.size()) == 0);
            if (match) {
                ComPtr<ID3D11Device> tmpDev;
                ComPtr<ID3D11DeviceContext> tmpCtx;
                D3D_FEATURE_LEVEL fl{};
                HRESULT hrD = D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN,
                                                nullptr, 0, nullptr, 0,
                                                D3D11_SDK_VERSION,
                                                &tmpDev, &fl, &tmpCtx);
                if (FAILED(hrD)) {
                    fprintf(stderr, "ddxgi: D3D11CreateDevice hr=0x%08lX\n", (unsigned long)hrD);
                    output.Reset();
                    adapter.Reset();
                    continue;
                }
                ComPtr<IDXGIOutput1> out1;
                HRESULT hrDup = output.As(&out1);
                if (SUCCEEDED(hrDup)) {
                    hrDup = out1->DuplicateOutput(tmpDev.Get(), &dup);
                }
                if (FAILED(hrDup)) {
                    fprintf(stderr, "ddxgi: DuplicateOutput hr=0x%08lX\n", (unsigned long)hrDup);
                    output.Reset();
                    adapter.Reset();
                    continue;
                }
                dev = std::move(tmpDev);
                ctx = std::move(tmpCtx);
                goto FoundOutput;
            }
            ++cur;
            output.Reset();
        }
        adapter.Reset();
    }
    return false;

FoundOutput:
    ComPtr<ID3D11Texture2D> staging;
    ComPtr<IDXGIResource> res;
    DXGI_OUTDUPL_FRAME_INFO info{};
    HRESULT hr = E_FAIL;

    // Acquire a usable frame. A static desktop only presents ONCE (the
    // initial accumulated frame, often with LastPresentTime == 0) — demanding
    // a nonzero present time here deadlocks on idle desktops.
    for (int retry = 0; retry < 20; ++retry) {
        hr = dup->AcquireNextFrame(250, &info, &res);
        if (SUCCEEDED(hr)) {
            if (info.LastPresentTime.QuadPart != 0 || info.AccumulatedFrames > 0) break;
            dup->ReleaseFrame();
            continue;
        }
        if (hr != DXGI_ERROR_WAIT_TIMEOUT) {
            fprintf(stderr, "ddxgi: AcquireNextFrame hr=0x%08lX\n", (unsigned long)hr);
            return false;
        }
    }
    if (FAILED(hr)) {
        fprintf(stderr, "ddxgi: AcquireNextFrame timed out (static desktop?)\n");
        return false;
    }

    ComPtr<ID3D11Texture2D> frame;
    res.As(&frame);
    D3D11_TEXTURE2D_DESC td{};
    frame->GetDesc(&td);

    D3D11_TEXTURE2D_DESC stDesc = td;
    stDesc.Usage = D3D11_USAGE_STAGING;
    stDesc.BindFlags = 0;
    stDesc.MiscFlags = 0;
    stDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    if (FAILED(dev->CreateTexture2D(&stDesc, nullptr, &staging))) {
        dup->ReleaseFrame();
        return false;
    }

    ctx->CopyResource(staging.Get(), frame.Get());
    dup->ReleaseFrame();

    D3D11_MAPPED_SUBRESOURCE map{};
    if (FAILED(ctx->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
        return false;
    }

    outW = td.Width;
    outH = td.Height;
    bool ok = false;

    if (td.Format == DXGI_FORMAT_B8G8R8A8_UNORM) {
        ok = EncodeBgraToPngWic((const uint8_t*)map.pData, td.Width, td.Height,
                                map.RowPitch, outPng);
    } else if (td.Format == DXGI_FORMAT_R16G16B16A16_FLOAT) {
        // HDR: approximate Reinhard tone-map FP16 -> BGRA8 (see file comment).
        std::vector<uint8_t> bgra((size_t)td.Width * td.Height * 4);
        for (UINT y = 0; y < td.Height; ++y) {
            const uint16_t* row = (const uint16_t*)((const uint8_t*)map.pData + y * map.RowPitch);
            uint8_t* dst = bgra.data() + (size_t)y * td.Width * 4;
            for (UINT x = 0; x < td.Width; ++x) {
                float r = (row[x * 4 + 0] & 0x7FFF) / 1024.0f;
                float g = (row[x * 4 + 1] & 0x7FFF) / 1024.0f;
                float b = (row[x * 4 + 2] & 0x7FFF) / 1024.0f;
                dst[x * 4 + 0] = (uint8_t)(std::clamp(b / (1.0f + b), 0.0f, 1.0f) * 255.0f);
                dst[x * 4 + 1] = (uint8_t)(std::clamp(g / (1.0f + g), 0.0f, 1.0f) * 255.0f);
                dst[x * 4 + 2] = (uint8_t)(std::clamp(r / (1.0f + r), 0.0f, 1.0f) * 255.0f);
                dst[x * 4 + 3] = 255;
            }
        }
        ok = EncodeBgraToPngWic(bgra.data(), td.Width, td.Height,
                                td.Width * 4, outPng);
    }

    ctx->Unmap(staging.Get(), 0);
    return ok;
}

// ---------------------------------------------------------------- displays ----

namespace {

struct DispCtx {
    std::ostringstream* ss;
    bool first;
};

BOOL CALLBACK DispEnumProc(HMONITOR hmon, HDC, LPRECT, LPARAM lp)
{
    auto* c = reinterpret_cast<DispCtx*>(lp);
    MONITORINFOEXW mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(hmon, &mi)) {
        return TRUE;
    }
    if (!c->first) *(c->ss) << ",";
    c->first = false;
    *(c->ss) << "{\"device\":\"" << JsonEscape(mi.szDevice) << "\""
             << ",\"primary\":" << ((mi.dwFlags & MONITORINFOF_PRIMARY) ? "true" : "false")
             << ",\"rect\":{\"x\":" << mi.rcMonitor.left
             << ",\"y\":" << mi.rcMonitor.top
             << ",\"width\":" << (mi.rcMonitor.right - mi.rcMonitor.left)
             << ",\"height\":" << (mi.rcMonitor.bottom - mi.rcMonitor.top) << "}"
             << ",\"work_rect\":{\"x\":" << mi.rcWork.left
             << ",\"y\":" << mi.rcWork.top
             << ",\"width\":" << (mi.rcWork.right - mi.rcWork.left)
             << ",\"height\":" << (mi.rcWork.bottom - mi.rcWork.top) << "}}";
    return TRUE;
}

} // namespace

bool CaptureDisplaysJson(std::string& outJson)
{
    std::ostringstream ss;
    ss << "{\"displays\":[";
    DispCtx c{ &ss, true };
    EnumDisplayMonitors(nullptr, nullptr, DispEnumProc, (LPARAM)&c);
    ss << "]}";
    outJson = ss.str();
    return true;
}

} // namespace screen
} // namespace suspex
