// mapper.exe — custom manual-map loader for kernel images.
//
// Pipeline: read image → KMEM_ALLOC in target kernel → stage VA image
// (headers + sections) → apply DIR64 relocations → resolve imports against
// kernel module export tables (read through the driver) → write image →
// trigger entry via kernel-mode APC on an alertable remote thread.
//
// Image contract: entry runs as void entry(PVOID a1, PVOID a2, PVOID a3) with
// (NULL, NULL, NULL) from this loader; kernel mode, PASSIVE_LEVEL-ish (APC
// level). Images must tolerate no DriverObject/RegistryPath. HVCI must be off.

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "suspex_comm.h"

using namespace suspex;

static Driver g_drv;

static std::vector<BYTE> ReadFileBytes(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return {};
    }
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    std::vector<BYTE> buf((size_t)sz.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr);
    CloseHandle(h);
    if (!ok || read != buf.size()) {
        return {};
    }
    return buf;
}

static std::wstring Lower(std::wstring s)
{
    for (auto& c : s) {
        c = (WCHAR)towlower(c);
    }
    return s;
}

struct KernelExports {
    UINT64 base = 0;
    std::vector<BYTE> headers; // first 4 KiB of module
};

static bool ReadKernelMem(UINT64 addr, void* dst, size_t len)
{
    SIZE_T got = 0;
    return g_drv.MemRead(Space::Kernel, 0, addr, dst, len, &got) && got == len;
}

static bool WriteKernelMem(UINT64 addr, const void* src, size_t len)
{
    SIZE_T w = 0;
    return g_drv.MemWrite(Space::Kernel, 0, addr, src, len, &w) && w == len;
}

// resolve export `name` in kernel module at `modBase` by walking its export
// directory through kernel reads
static bool ResolveKernelExport(UINT64 modBase, const std::string& name, UINT64* out)
{
    unsigned char hdr[4096];
    if (!ReadKernelMem(modBase, hdr, sizeof(hdr))) {
        return false;
    }
    auto* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exportRva || !exportSize) {
        return false;
    }
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadKernelMem(modBase + exportRva, &exp, sizeof(exp))) {
        return false;
    }
    if (!exp.NumberOfNames || exp.NumberOfNames > 200000) {
        return false;
    }
    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<WORD> ordinals(exp.NumberOfNames);
    if (!ReadKernelMem(modBase + exp.AddressOfNames, names.data(), names.size() * sizeof(DWORD))) {
        return false;
    }
    if (!ReadKernelMem(modBase + exp.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD))) {
        return false;
    }
    char cur[192];
    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        if (!ReadKernelMem(modBase + names[i], cur, sizeof(cur))) {
            continue;
        }
        cur[sizeof(cur) - 1] = 0;
        if (name == cur) {
            DWORD fnRva = 0;
            if (!ReadKernelMem(modBase + exp.AddressOfFunctions + (size_t)ordinals[i] * sizeof(DWORD),
                               &fnRva, sizeof(fnRva))) {
                return false;
            }
            *out = modBase + fnRva;
            return true;
        }
    }
    return false;
}

static UINT64 FindKernelModule(const std::vector<ModuleEntry>& mods, const std::wstring& name,
                               UINT64* sizeOut = nullptr)
{
    std::wstring want = Lower(name);
    for (auto& m : mods) {
        if (Lower(m.Name) == want) {
            if (sizeOut) {
                *sizeOut = m.Size;
            }
            return m.Base;
        }
    }
    return 0;
}

// create a parked alertable thread in the target to host the APC
static DWORD CreateParkedThread(UINT32 pid, std::string* err)
{
    std::vector<ModuleEntry> mods;
    if (!g_drv.UserModules(pid, mods)) {
        *err = "UserModules: " + g_drv.LastError();
        return 0;
    }
    UINT64 kbBase = FindKernelModule(mods, L"kernelbase.dll");
    if (!kbBase) {
        *err = "kernelbase.dll not found in target";
        return 0;
    }
    HMODULE kbLocal = GetModuleHandleW(L"kernelbase.dll");
    FARPROC sleepExLocal = kbLocal ? GetProcAddress(kbLocal, "SleepEx") : nullptr;
    if (!sleepExLocal) {
        *err = "local SleepEx resolution failed";
        return 0;
    }
    // same-boot ASLR: module bases are equal across processes
    UINT64 sleepExTarget = (UINT64)((uintptr_t)sleepExLocal) - (UINT64)(uintptr_t)kbLocal + kbBase;

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
                              FALSE, pid);
    if (!proc) {
        *err = "OpenProcess failed gle=" + std::to_string(GetLastError());
        return 0;
    }
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)sleepExTarget,
                                       (LPVOID)(uintptr_t)0xFFFFFFFF, CREATE_SUSPENDED, nullptr);
    CloseHandle(proc);
    if (!thread) {
        *err = "CreateRemoteThread failed gle=" + std::to_string(GetLastError());
        return 0;
    }
    DWORD tid = GetThreadId(thread);
    if (ResumeThread(thread) == (DWORD)-1) {
        CloseHandle(thread);
        *err = "ResumeThread failed";
        return 0;
    }
    // leak the handle intentionally: closing it could end the parked thread if
    // nobody else references it
    return tid;
}

int wmain(int argc, wchar_t** argv)
{
    UINT32 pid = 0;
    std::wstring imagePath;
    DWORD explicitTid = 0;

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--pid") && i + 1 < argc) {
            pid = (UINT32)wcstoul(argv[++i], nullptr, 0);
        } else if (!wcscmp(argv[i], L"--image") && i + 1 < argc) {
            imagePath = argv[++i];
        } else if (!wcscmp(argv[i], L"--tid") && i + 1 < argc) {
            explicitTid = (DWORD)wcstoul(argv[++i], nullptr, 0);
        }
    }
    if (!pid || imagePath.empty()) {
        wprintf(L"usage: mapper.exe --pid <pid> --image <path.sys> [--tid <alertable tid>]\n");
        return 2;
    }

    if (!g_drv.Open()) {
        wprintf(L"driver open failed: %hs\n", g_drv.LastError().c_str());
        return 1;
    }

    PingInfo ping{};
    if (!g_drv.Ping(&ping)) {
        wprintf(L"driver ping failed: %hs\n", g_drv.LastError().c_str());
        return 1;
    }
    if (ping.Flags & SUSPEX_FLAG_HVCI) {
        wprintf(L"HVCI is enabled: manual mapping is blocked by VBS. Disable HVCI on the target.\n");
        return 1;
    }

    std::vector<BYTE> pe = ReadFileBytes(imagePath);
    if (pe.empty()) {
        wprintf(L"failed to read %s\n", imagePath.c_str());
        return 1;
    }
    auto* dos = (IMAGE_DOS_HEADER*)pe.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        wprintf(L"not a PE image\n");
        return 1;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(pe.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        wprintf(L"not an x64 PE image\n");
        return 1;
    }
    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;

    UINT64 base = 0;
    if (!g_drv.KmemAlloc(sizeOfImage, &base)) {
        wprintf(L"kalloc failed: %hs\n", g_drv.LastError().c_str());
        return 1;
    }
    wprintf(L"kernel alloc %p (%lu bytes)\n", (void*)(uintptr_t)base, sizeOfImage);

    const INT64 delta = (INT64)base - (INT64)nt->OptionalHeader.ImageBase;
    std::vector<BYTE> image(sizeOfImage, 0);
    memcpy(image.data(), pe.data(), nt->OptionalHeader.SizeOfHeaders);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD copy = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData
                                                                    : sec[i].Misc.VirtualSize;
        if (sec[i].PointerToRawData && copy) {
            memcpy(image.data() + sec[i].VirtualAddress, pe.data() + sec[i].PointerToRawData, copy);
        }
    }

    // relocations
    IMAGE_DATA_DIRECTORY& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size && delta != 0) {
        BYTE* r = image.data() + relocDir.VirtualAddress;
        BYTE* end = r + relocDir.Size;
        while (r + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            auto* block = (IMAGE_BASE_RELOCATION*)r;
            if (!block->SizeOfBlock) {
                break;
            }
            WORD* entries = (WORD*)(r + sizeof(IMAGE_BASE_RELOCATION));
            DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD j = 0; j < count; j++) {
                WORD type = entries[j] >> 12;
                WORD off = entries[j] & 0xFFF;
                UINT64* patch;
                switch (type) {
                case IMAGE_REL_BASED_DIR64:
                    patch = (UINT64*)(image.data() + block->VirtualAddress + off);
                    *patch = (UINT64)((INT64)*patch + delta);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    wprintf(L"unsupported reloc type %u\n", type);
                    return 1;
                }
            }
            r += block->SizeOfBlock;
        }
    }

    // imports: resolve against kernel modules
    IMAGE_DATA_DIRECTORY& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        std::vector<ModuleEntry> kmods;
        if (!g_drv.KernelModules(kmods)) {
            wprintf(L"kernel modules walk failed: %hs\n", g_drv.LastError().c_str());
            return 1;
        }
        for (auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(image.data() + impDir.VirtualAddress);
             desc->Name; desc++) {
            const char* dllName = (const char*)(image.data() + desc->Name);
            UINT64 modBase = FindKernelModule(kmods, std::wstring(dllName, dllName + strlen(dllName)));
            if (!modBase) {
                wprintf(L"import dll not found in kernel: %hs\n", dllName);
                return 1;
            }
            wprintf(L"  import %hs @ %p\n", dllName, (void*)(uintptr_t)modBase);
            PIMAGE_THUNK_DATA intThunk = desc->OriginalFirstThunk
                                             ? (PIMAGE_THUNK_DATA)(image.data() + desc->OriginalFirstThunk)
                                             : (PIMAGE_THUNK_DATA)(image.data() + desc->FirstThunk);
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(image.data() + desc->FirstThunk);
            for (int idx = 0; intThunk[idx].u1.AddressOfData; idx++) {
                if (intThunk[idx].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    wprintf(L"  ordinal imports unsupported\n");
                    return 1;
                }
                auto* importByName = (IMAGE_IMPORT_BY_NAME*)(image.data() +
                                                             ((UINT64)intThunk[idx].u1.AddressOfData & 0xFFFFFFFF));
                UINT64 resolved = 0;
                if (!ResolveKernelExport(modBase, importByName->Name, &resolved)) {
                    wprintf(L"  export not found: %hs!%hs (forwarded exports unsupported)\n",
                            dllName, importByName->Name);
                    return 1;
                }
                iat[idx].u1.Function = resolved;
            }
        }
    }

    // write staged image to kernel
    const DWORD kChunk = 0x10000;
    for (DWORD off = 0; off < sizeOfImage; off += kChunk) {
        DWORD n = (std::min)(kChunk, sizeOfImage - off);
        if (!WriteKernelMem(base + off, image.data() + off, n)) {
            wprintf(L"kwrite failed at +%lx: %hs\n", off, g_drv.LastError().c_str());
            return 1;
        }
    }

    DWORD tid = explicitTid;
    if (!tid) {
        std::string err;
        tid = CreateParkedThread(pid, &err);
        if (!tid) {
            wprintf(L"parked thread: %hs\n", err.c_str());
            return 1;
        }
    }
    wprintf(L"triggering entry +%lx via kernel APC on tid %lu\n", entryRva, tid);

    bool queued = false, alerted = false;
    if (!g_drv.RemoteCall(pid, tid, base + entryRva, 0, 0, 0, SUSPEX_RC_FLAG_KERNEL, &queued, &alerted) || !queued) {
        wprintf(L"APC trigger failed: %hs\n", g_drv.LastError().c_str());
        return 1;
    }
    wprintf(L"mapped: base=%p entry=%p (image owns its own completion signalling; do NOT kfree a running image)\n",
            (void*)(uintptr_t)base, (void*)(uintptr_t)(base + entryRva));
    return 0;
}
