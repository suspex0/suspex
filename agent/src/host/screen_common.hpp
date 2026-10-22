// Screen / window telemetry — shared definitions for the session-1 worker
// (--screenshot child) and the Session-0 dispatcher.
//
// Wire: the worker writes one ScreenIpcHeader followed by the PNG payload and
// a JSON metadata blob to the inherited pipe handle. The dispatcher reads it
// back with a hard deadline (screen_dispatch.cpp) and forwards the JSON to the
// orchestrator untouched — the agent carries no JSON parser.
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincodec.h>

#include <cstdint>
#include <string>
#include <vector>

namespace suspex {
namespace screen {

// --screenshot child entry (screen_worker.cpp). Declared here so main()'s
// fast-path hook sees one canonical prototype.
int RunScreenWorkerCli(int argc, char** argv);

#pragma pack(push, 1)
struct ScreenIpcHeader {
    uint32_t magic;      // 'SCRN' little-endian (0x4E524353)
    uint32_t status;     // 0 = OK, >0 = Win32/custom error
    uint32_t width;
    uint32_t height;
    uint32_t png_len;    // PNG payload length (0 for list/displays)
    uint32_t json_len;   // JSON metadata payload length
};
#pragma pack(pop)

constexpr uint32_t SCREEN_IPC_MAGIC = 0x4E524353;

// ---------------------------------------------------------------- text ----

inline std::string ToUtf8(const std::wstring& ws)
{
    if (ws.empty()) {
        return {};
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? n : 0, '\0');
    if (n > 0) {
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
                            out.data(), n, nullptr, nullptr);
    }
    return out;
}

inline std::string JsonEscape(const std::wstring& ws)
{
    std::string s = ToUtf8(ws);
    std::string out;
    out.reserve(s.size() + 8);
    char b[8];
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if ((unsigned char)c < 0x20) {
                snprintf(b, sizeof(b), "\\u%04X", (unsigned char)c);
                out += b;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Hex-encoded UTF-8 CLI args (--title-hex / --proc-hex / --query-hex):
// arbitrary filter text survives the command line without quoting bugs.
inline std::string WsToHexArg(const std::wstring& ws)
{
    static const char* hex = "0123456789abcdef";
    const std::string utf8 = ToUtf8(ws);
    std::string out;
    out.reserve(utf8.size() * 2);
    for (unsigned char c : utf8) {
        out += hex[c >> 4];
        out += hex[c & 0xF];
    }
    return out;
}

inline std::wstring HexArgToWs(const std::string& hex)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string utf8;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            break;
        }
        utf8 += (char)((hi << 4) | lo);
    }
    if (utf8.empty()) {
        return L"";
    }
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                                nullptr, 0);
    std::wstring out(n > 0 ? n : 0, L'\0');
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                            out.data(), n);
    }
    return out;
}

// --------------------------------------------------------------- helpers ----

// pid -> (image basename, full path). PROCESS_QUERY_LIMITED_INFORMATION works
// against elevated processes from the medium-IL worker.
inline bool QueryProcessImage(DWORD pid, std::wstring& name, std::wstring& full)
{
    name.clear();
    full.clear();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        return false;
    }
    wchar_t path[MAX_PATH * 2]{};
    DWORD size = MAX_PATH * 2;
    bool ok = QueryFullProcessImageNameW(h, 0, path, &size) != 0;
    CloseHandle(h);
    if (!ok) {
        return false;
    }
    full = path;
    const wchar_t* slash = wcsrchr(path, L'\\');
    name = slash ? (slash + 1) : path;
    return true;
}

// ------------------------------------------------------------------ WIC ----

// BGRA 32bpp raw pixels -> PNG via the inproc WIC encoder. Returns false on
// any COM failure; the worker turns that into a nonzero IPC status.
inline bool EncodeBgraToPngWic(const uint8_t* bgra, uint32_t width, uint32_t height,
                               uint32_t stride, std::vector<uint8_t>& outPng)
{
    outPng.clear();
    if (!bgra || !width || !height) {
        return false;
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool coInit = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return false;
    }
    // COINIT changed-mode is fine: WIC is apartment-agnostic for this use.
    bool ok = false;
    IWICImagingFactory* factory = nullptr;
    IStream* stream = nullptr;
    IWICBitmapEncoder* encoder = nullptr;
    IWICBitmapFrameEncode* frame = nullptr;

    do {
        hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&factory));
        if (FAILED(hr)) break;
        hr = CreateStreamOnHGlobal(nullptr, TRUE, &stream);
        if (FAILED(hr)) break;
        hr = factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder);
        if (FAILED(hr)) break;
        hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
        if (FAILED(hr)) break;
        hr = encoder->CreateNewFrame(&frame, nullptr);
        if (FAILED(hr)) break;
        hr = frame->Initialize(nullptr);
        if (FAILED(hr)) break;
        hr = frame->SetSize(width, height);
        if (FAILED(hr)) break;
        WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
        hr = frame->SetPixelFormat(&format);
        if (FAILED(hr)) break;
        hr = frame->WritePixels(height, stride, stride * height,
                                const_cast<BYTE*>(bgra));
        if (FAILED(hr)) break;
        hr = frame->Commit();
        if (FAILED(hr)) break;
        hr = encoder->Commit();
        if (FAILED(hr)) break;

        STATSTG stat{};
        if (FAILED(stream->Stat(&stat, STATFLAG_NONAME)) || !stat.cbSize.QuadPart) {
            break;
        }
        const ULONG bytesLen = (ULONG)stat.cbSize.QuadPart;
        outPng.resize(bytesLen);
        LARGE_INTEGER li{};
        if (FAILED(stream->Seek(li, STREAM_SEEK_SET, nullptr))) {
            break;
        }
        ULONG readBytes = 0;
        if (FAILED(stream->Read(outPng.data(), bytesLen, &readBytes)) ||
            readBytes != bytesLen) {
            outPng.clear();
            break;
        }
        ok = true;
    } while (false);

    if (frame) frame->Release();
    if (encoder) encoder->Release();
    if (stream) stream->Release();
    if (factory) factory->Release();
    if (coInit) CoUninitialize();
    return ok;
}

} // namespace screen
} // namespace suspex
