// Window capture via C++/WinRT Windows.Graphics.Capture (WGC).
//
// Needs Win10 1903+ (GraphicsCaptureSession::IsSupported gates it). Capturing
// a MINIMIZED window yields a stale/black frame — callers consult the
// `minimized` / `show_cmd` flags from the window list first.
//
// Includes are order-sensitive: the SDK interop headers declare interfaces in
// the GLOBAL ::Windows namespace (not ABI::), so `using namespace winrt;`
// would make `Windows` ambiguous. Everything is winrt::-qualified instead.
//
// FrameArrived state lives in shared_ptrs captured BY VALUE: on the timeout
// path session.Close()/pool.Close() can still deliver a late frame that runs
// after this function returned — nothing may point at our stack.
#include "screen_common.hpp"

#include <d3d11.h>
#include <dxgi.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>

#include <chrono>
#include <future>
#include <memory>
#include <utility>

namespace {

namespace wgc = winrt::Windows::Graphics::Capture;
namespace dx = winrt::Windows::Graphics::DirectX;
namespace dx11 = winrt::Windows::Graphics::DirectX::Direct3D11;
namespace dx11interop = ::Windows::Graphics::DirectX::Direct3D11;

struct CaptureResult {
    std::vector<uint8_t> png;
    uint32_t w = 0, h = 0;
    bool ok = false;
};

} // namespace

namespace suspex {
namespace screen {

bool CaptureWindowWgc(HWND hwnd, std::vector<uint8_t>& outPng,
                      uint32_t& outW, uint32_t& outH)
{
    outPng.clear();
    outW = outH = 0;

    if (!hwnd || !IsWindow(hwnd)) {
        return false;
    }
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);

        if (!wgc::GraphicsCaptureSession::IsSupported()) {
            return false;   // WGC needs Win10 1903+
        }

        // IGraphicsCaptureItemInterop is a global-ns COM interface declared
        // by windows.graphics.capture.interop.h.
        auto interop = winrt::get_activation_factory<wgc::GraphicsCaptureItem,
                                                     ::IGraphicsCaptureItemInterop>();
        wgc::GraphicsCaptureItem item{ nullptr };
        if (FAILED(interop->CreateForWindow(
                hwnd, winrt::guid_of<wgc::GraphicsCaptureItem>(),
                winrt::put_abi(item)))) {
            return false;
        }

        winrt::com_ptr<ID3D11Device> dev;
        winrt::com_ptr<ID3D11DeviceContext> ctx;
        if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                                     D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                     nullptr, 0, D3D11_SDK_VERSION,
                                     dev.put(), nullptr, ctx.put()))) {
            return false;
        }

        dx11::IDirect3DDevice winrtDev{ nullptr };
        if (FAILED(CreateDirect3D11DeviceFromDXGIDevice(
                dev.as<IDXGIDevice>().get(),
                reinterpret_cast<::IInspectable**>(winrt::put_abi(winrtDev))))) {
            return false;
        }

        auto pool = wgc::Direct3D11CaptureFramePool::CreateFreeThreaded(
            winrtDev, dx::DirectXPixelFormat::B8G8R8A8UIntNormalized, 1,
            item.Size());
        auto session = pool.CreateCaptureSession(item);
        session.IsCursorCaptureEnabled(false);

        auto state = std::make_shared<std::promise<bool>>();
        auto result = std::make_shared<CaptureResult>();
        auto fut = state->get_future();

        pool.FrameArrived([state, dev, ctx, result](auto const& sender, auto const&) {
            auto settle = [state, result](bool v) {
                result->ok = v;
                try { state->set_value(v); } catch (...) {}   // double-set after timeout
            };
            auto frame = sender.TryGetNextFrame();
            if (!frame) {
                settle(false);
                return;
            }
            auto access =
                frame.Surface().as<dx11interop::IDirect3DDxgiInterfaceAccess>();
            winrt::com_ptr<ID3D11Texture2D> tex;
            if (FAILED(access->GetInterface(winrt::guid_of<ID3D11Texture2D>(),
                                            tex.put_void()))) {
                settle(false);
                return;
            }

            D3D11_TEXTURE2D_DESC td{};
            tex->GetDesc(&td);
            td.Usage = D3D11_USAGE_STAGING;
            td.BindFlags = 0;
            td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            td.MiscFlags = 0;

            winrt::com_ptr<ID3D11Texture2D> staging;
            if (FAILED(dev->CreateTexture2D(&td, nullptr, staging.put()))) {
                settle(false);
                return;
            }

            ctx->CopyResource(staging.get(), tex.get());
            D3D11_MAPPED_SUBRESOURCE map{};
            if (FAILED(ctx->Map(staging.get(), 0, D3D11_MAP_READ, 0, &map))) {
                settle(false);
                return;
            }

            result->w = td.Width;
            result->h = td.Height;
            result->ok = EncodeBgraToPngWic((const uint8_t*)map.pData,
                                            td.Width, td.Height,
                                            map.RowPitch, result->png);
            ctx->Unmap(staging.get(), 0);
            settle(result->ok);
        });

        session.StartCapture();
        const bool ok = fut.wait_for(std::chrono::seconds(3)) ==
                            std::future_status::ready &&
                        fut.get();
        session.Close();
        pool.Close();
        if (ok) {
            outPng = std::move(result->png);
            outW = result->w;
            outH = result->h;
        }
        return ok;
    } catch (...) {
        return false;
    }
}

} // namespace screen
} // namespace suspex
