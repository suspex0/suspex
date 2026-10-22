// Build-independent PE walker (see pe_reader.hpp).
//
// Portions adapted from ReverseKit (MIT), zer0condition/ReverseKit
//   ReverseKit/Imports/Imports.cpp @ master

#include "pe_reader.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>

namespace suspex::pe {

namespace {

constexpr uint64_t kMaxImageSize = 512ull * 1024 * 1024; // 512 MiB sanity cap
constexpr size_t kMaxDllName = 260;
constexpr size_t kMaxFuncName = 512;
constexpr uint32_t kMaxImports = 65536;
constexpr uint32_t kMaxExports = 65536;

struct Header {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    uint32_t size_of_image;
    uint32_t import_rva;
    uint32_t import_size;
    uint32_t export_rva;
    uint32_t export_size;
};

// Read null-terminated ASCII string via `read` at (base + rva); caps at `max`.
bool ReadCString(ReadFn& read, uint64_t addr, size_t max, std::string& out)
{
    out.clear();
    char buf[64];
    while (out.size() < max) {
        size_t chunk = std::min<size_t>(sizeof(buf), max - out.size());
        if (!read(addr + out.size(), buf, chunk)) {
            return false;
        }
        for (size_t i = 0; i < chunk; ++i) {
            if (buf[i] == '\0') {
                out.append(buf, i);
                return true;
            }
        }
        out.append(buf, chunk);
    }
    return true; // hit the cap; caller decides if that's acceptable
}

bool ReadHeader(uint64_t base, ReadFn& read, Header& h, std::string* err)
{
    if (!read(base, &h.dos, sizeof(h.dos))) {
        if (err) *err = "read DOS header";
        return false;
    }
    if (h.dos.e_magic != IMAGE_DOS_SIGNATURE) {
        if (err) *err = "bad DOS signature";
        return false;
    }
    if (h.dos.e_lfanew <= 0 || (uint64_t)h.dos.e_lfanew > kMaxImageSize) {
        if (err) *err = "bad e_lfanew";
        return false;
    }
    if (!read(base + (uint64_t)h.dos.e_lfanew, &h.nt, sizeof(h.nt))) {
        if (err) *err = "read NT headers";
        return false;
    }
    if (h.nt.Signature != IMAGE_NT_SIGNATURE) {
        if (err) *err = "bad NT signature";
        return false;
    }
    if (h.nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (err) *err = "not PE32+";
        return false;
    }
    h.size_of_image = h.nt.OptionalHeader.SizeOfImage;
    if (h.size_of_image == 0 || h.size_of_image > kMaxImageSize) {
        if (err) *err = "bad SizeOfImage";
        return false;
    }
    const auto& imp = h.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const auto& exp = h.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    h.import_rva = imp.VirtualAddress;
    h.import_size = imp.Size;
    h.export_rva = exp.VirtualAddress;
    h.export_size = exp.Size;
    return true;
}

bool RvaInImage(const Header& h, uint32_t rva, uint32_t need = 1)
{
    if (rva == 0 || need == 0) return false;
    if (rva > h.size_of_image) return false;
    return (uint64_t)rva + need <= h.size_of_image;
}

} // namespace

bool ParseImports(uint64_t base, ReadFn read, std::vector<IatRow>& out, std::string* err)
{
    Header h{};
    if (!ReadHeader(base, read, h, err)) return false;
    if (!RvaInImage(h, h.import_rva, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
        return true; // no imports is a legal outcome
    }

    uint32_t desc_off = h.import_rva;
    uint32_t emitted = 0;
    for (uint32_t di = 0; di < kMaxImports; ++di) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!RvaInImage(h, desc_off, sizeof(desc))) break;
        if (!read(base + desc_off, &desc, sizeof(desc))) {
            if (err && err->empty()) *err = "read import descriptor";
            break;
        }
        if (desc.Name == 0 && desc.FirstThunk == 0) break;
        if (!RvaInImage(h, desc.Name, 1)) {
            desc_off += sizeof(desc);
            continue;
        }
        std::string dll;
        if (!ReadCString(read, base + desc.Name, kMaxDllName, dll)) {
            desc_off += sizeof(desc);
            continue;
        }
        // OriginalFirstThunk (INT) is the stable name table; FirstThunk (IAT)
        // is what the loader overwrites with resolved pointers. Walk INT for
        // names; walk IAT slot-by-slot in parallel for resolved values.
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                   : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;
        if (!RvaInImage(h, iat_rva, sizeof(uint64_t))) {
            desc_off += sizeof(desc);
            continue;
        }
        uint32_t i = 0;
        for (; i < kMaxImports; ++i) {
            uint32_t int_slot_rva = int_rva + i * sizeof(uint64_t);
            uint32_t iat_slot_rva = iat_rva + i * sizeof(uint64_t);
            if (!RvaInImage(h, int_slot_rva, sizeof(uint64_t))) break;
            if (!RvaInImage(h, iat_slot_rva, sizeof(uint64_t))) break;
            uint64_t int_val = 0, iat_val = 0;
            if (!read(base + int_slot_rva, &int_val, sizeof(int_val))) break;
            if (!read(base + iat_slot_rva, &iat_val, sizeof(iat_val))) break;
            if (int_val == 0) break;

            IatRow row{};
            row.dll = dll;
            row.iat_slot = base + iat_slot_rva;
            row.resolved = iat_val;
            if (int_val & IMAGE_ORDINAL_FLAG64) {
                row.ordinal = (uint32_t)(int_val & 0xFFFF);
            } else {
                uint32_t iname_rva = (uint32_t)(int_val & 0xFFFFFFFF);
                if (RvaInImage(h, iname_rva, 2 + 1)) {
                    // IMAGE_IMPORT_BY_NAME: WORD Hint, CHAR Name[]
                    uint64_t name_addr = base + iname_rva + 2;
                    ReadCString(read, name_addr, kMaxFuncName, row.name);
                }
            }
            out.push_back(std::move(row));
            if (++emitted >= kMaxImports) break;
        }
        if (emitted >= kMaxImports) break;
        desc_off += sizeof(desc);
    }
    return true;
}

bool ParseExports(uint64_t base, ReadFn read, std::vector<ExpRow>& out, std::string* err)
{
    Header h{};
    if (!ReadHeader(base, read, h, err)) return false;
    if (!RvaInImage(h, h.export_rva, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return true; // module without exports is fine
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!read(base + h.export_rva, &exp, sizeof(exp))) {
        if (err) *err = "read export directory";
        return false;
    }
    if (exp.NumberOfFunctions == 0) return true;
    if (exp.NumberOfFunctions > kMaxExports) exp.NumberOfFunctions = kMaxExports;
    if (exp.NumberOfNames > exp.NumberOfFunctions) exp.NumberOfNames = exp.NumberOfFunctions;

    // Build reverse index: function-slot -> exported-name (via ordinal table)
    std::vector<std::string> names_by_slot(exp.NumberOfFunctions);
    if (exp.NumberOfNames &&
        RvaInImage(h, exp.AddressOfNames, exp.NumberOfNames * 4) &&
        RvaInImage(h, exp.AddressOfNameOrdinals, exp.NumberOfNames * 2)) {
        std::vector<uint32_t> name_rvas(exp.NumberOfNames);
        std::vector<uint16_t> ord_slots(exp.NumberOfNames);
        if (!read(base + exp.AddressOfNames, name_rvas.data(),
                  name_rvas.size() * sizeof(uint32_t))) {
            if (err) *err = "read AddressOfNames";
        } else if (!read(base + exp.AddressOfNameOrdinals, ord_slots.data(),
                         ord_slots.size() * sizeof(uint16_t))) {
            if (err) *err = "read AddressOfNameOrdinals";
        } else {
            for (uint32_t i = 0; i < exp.NumberOfNames; ++i) {
                // AddressOfNameOrdinals[i] is a direct 0-based slot into
                // AddressOfFunctions — NOT relative to Base. Subtracting Base
                // is a classic export-walker off-by-one (see PLAN_NEXT §10).
                uint16_t slot = ord_slots[i];
                if (slot >= exp.NumberOfFunctions) continue;
                if (!RvaInImage(h, name_rvas[i], 1)) continue;
                ReadCString(read, base + name_rvas[i], kMaxFuncName, names_by_slot[slot]);
            }
        }
    }

    if (!RvaInImage(h, exp.AddressOfFunctions, exp.NumberOfFunctions * 4)) {
        return true;
    }
    std::vector<uint32_t> fn_rvas(exp.NumberOfFunctions);
    if (!read(base + exp.AddressOfFunctions, fn_rvas.data(),
              fn_rvas.size() * sizeof(uint32_t))) {
        if (err) *err = "read AddressOfFunctions";
        return false;
    }

    uint32_t export_end = h.export_rva + h.export_size;
    for (uint32_t i = 0; i < exp.NumberOfFunctions; ++i) {
        uint32_t rva = fn_rvas[i];
        if (rva == 0) continue; // deleted/gap slot
        ExpRow row{};
        row.name = std::move(names_by_slot[i]);
        row.ordinal = exp.Base + i;
        row.rva = rva;
        // Forwarder: RVA points inside the export directory itself, and the
        // string "dll.symbol" (or "dll.#ord") lives there.
        if (rva >= h.export_rva && rva < export_end) {
            ReadCString(read, base + rva, kMaxFuncName, row.forwarder);
        }
        out.push_back(std::move(row));
    }
    return true;
}

} // namespace suspex::pe
