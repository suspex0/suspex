#include "dumper.hpp"
#include "../files.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace suspex {

// hard limits: the target's headers are hostile until proven otherwise
static const DWORD kMaxHeaders = 0x1000;      // first read window
static const WORD kMaxSections = 96;          // (4096 - sizeof(hdrs)) / 40
static const DWORD kMaxSectionChunk = 0x10000;

ModuleDumper::Result ModuleDumper::Dump(void* readerCtx, Reader reader, UINT32 pid, UINT64 base,
                                        DumpType type)
{
    Result res;
    std::vector<BYTE> hdr(kMaxHeaders);
    if (!reader(readerCtx, pid, base, hdr.data(), hdr.size())) {
        res.error = "failed to read PE headers";
        return res;
    }
    auto* dos = (IMAGE_DOS_HEADER*)hdr.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        res.error = "bad MZ at module base";
        return res;
    }
    LONG e_lfanew = dos->e_lfanew;
    if (e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
        (SIZE_T)e_lfanew + sizeof(IMAGE_NT_HEADERS64) > hdr.size()) {
        res.error = "e_lfanew out of bounds (malformed/hostile headers)";
        return res;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(hdr.data() + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        res.error = "bad PE signature";
        return res;
    }
    if (nt->FileHeader.NumberOfSections > kMaxSections ||
        (SIZE_T)e_lfanew + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader +
                sizeof(DWORD) + (SIZE_T)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) >
            hdr.size()) {
        res.error = "section table out of bounds (malformed/hostile headers)";
        return res;
    }
    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    if (sizeOfImage < sizeOfHeaders || sizeOfImage > (256u << 20) ||
        sizeOfHeaders > hdr.size() || sizeOfHeaders < e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
        res.error = "SizeOfHeaders/SizeOfImage out of bounds";
        return res;
    }
    res.image.assign(sizeOfImage, 0);
    memcpy(res.image.data(), hdr.data(), sizeOfHeaders);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsize = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (!vsize) {
            continue;
        }
        if ((UINT64)va >= sizeOfImage) {
            continue; // lies about its layout: skip rather than corrupt the dump
        }
        if ((UINT64)va + vsize > sizeOfImage) {
            vsize = (DWORD)(sizeOfImage - va); // clamp to the mapped image
        }
        // v0.24: per-section residency — a failed chunk read stops the
        // section's tail reading as silently-zero (PAGE/INIT discard etc.).
        SectionInfo info;
        info.name.assign(reinterpret_cast<const char*>(sec[i].Name),
                         strnlen_s(reinterpret_cast<const char*>(sec[i].Name),
                                   sizeof(sec[i].Name)));
        info.va = va;
        info.size = vsize;
        DWORD off = 0;
        while (off < vsize) {
            DWORD chunk = (vsize - off) < kMaxSectionChunk ? (vsize - off) : kMaxSectionChunk;
            if (!reader(readerCtx, pid, base + va + off, res.image.data() + va + off, chunk)) {
                break; // partial section: leave the tail zeroed
            }
            off += chunk;
        }
        info.dumped_bytes = off;
        info.complete = (off == vsize);
        res.sections.push_back(std::move(info));
    }

    // align file layout onto the VA layout
    auto* ntOut = (IMAGE_NT_HEADERS64*)(res.image.data() + e_lfanew);
    auto* secOut = IMAGE_FIRST_SECTION(ntOut);
    DWORD fileAlign = ntOut->OptionalHeader.FileAlignment ? ntOut->OptionalHeader.FileAlignment : 0x200;
    for (WORD i = 0; i < ntOut->FileHeader.NumberOfSections; i++) {
        DWORD vsize = secOut[i].Misc.VirtualSize ? secOut[i].Misc.VirtualSize : secOut[i].SizeOfRawData;
        secOut[i].PointerToRawData = (secOut[i].VirtualAddress / fileAlign) * fileAlign;
        secOut[i].SizeOfRawData = vsize;
    }

    // repair the debug directory: in a VA dump the CodeView blob stays at its
    // VA, so the entry must resolve through AddressOfRawData (mapped-image
    // form) instead of PointerToRawData (file form) for IDA to find the PDB
    {
        IMAGE_DATA_DIRECTORY& dbg = ntOut->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (dbg.VirtualAddress && dbg.Size >= sizeof(IMAGE_DEBUG_DIRECTORY) &&
            (UINT64)dbg.VirtualAddress + dbg.Size <= sizeOfImage) {
            DWORD count = dbg.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            if (count > 32) {
                count = 32;
            }
            for (DWORD i = 0; i < count; i++) {
                auto* de = (IMAGE_DEBUG_DIRECTORY*)(res.image.data() + dbg.VirtualAddress +
                                                     i * sizeof(IMAGE_DEBUG_DIRECTORY));
                if (de->Type != IMAGE_DEBUG_TYPE_CODEVIEW || !de->AddressOfRawData) {
                    continue;
                }
                // blob already lives at AddressOfRawData in the VA dump; keep
                // the VA and size authoritative, zero the file pointer
                de->PointerToRawData = 0;
                de->SizeOfData = de->SizeOfData ? de->SizeOfData : 0;
            }
        }
    }

    const INT64 delta = (INT64)base - (INT64)ntOut->OptionalHeader.ImageBase;
    if (type == DUMP_UNRELOCATED && delta != 0) {
        // reverse the loader's DIR64 relocations so the image diffs cleanly
        // against the on-disk binary, and restore the preferred ImageBase
        IMAGE_DATA_DIRECTORY& relocDir =
            ntOut->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size &&
            (UINT64)relocDir.VirtualAddress + relocDir.Size <= sizeOfImage) {
            BYTE* r = res.image.data() + relocDir.VirtualAddress;
            BYTE* end = r + relocDir.Size;
            while (r + sizeof(IMAGE_BASE_RELOCATION) <= end) {
                auto* block = (IMAGE_BASE_RELOCATION*)r;
                if (!block->SizeOfBlock || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                    break;
                }
                if ((SIZE_T)(r - res.image.data()) + block->SizeOfBlock > sizeOfImage) {
                    break;
                }
                WORD* entries = (WORD*)(r + sizeof(IMAGE_BASE_RELOCATION));
                DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (DWORD j = 0; j < count; j++) {
                    WORD eType = entries[j] >> 12;
                    WORD eOff = entries[j] & 0xFFF;
                    if (eType == IMAGE_REL_BASED_DIR64) {
                        UINT64 patchVa = (UINT64)block->VirtualAddress + eOff;
                        if (patchVa + sizeof(UINT64) <= sizeOfImage) {
                            UINT64* patch = (UINT64*)(res.image.data() + patchVa);
                            *patch = (UINT64)((INT64)*patch - delta);
                        }
                    }
                }
                r += block->SizeOfBlock;
            }
        }
        ntOut->OptionalHeader.ImageBase = base;
    }

    res.base = base;
    res.sizeOfImage = sizeOfImage;
    res.sha256 = Sha256HexBuf(res.image.data(), res.image.size());
    char baseHex[32];
    sprintf_s(baseHex, "%llX", (unsigned long long)base);
    res.notes = std::string("VA-dump reconstruction; sections at virtual addresses with aligned "
                            "PointerToRawData; IAT holds runtime-resolved pointers (run IDA with "
                            "loading address 0x") +
                baseHex;
    if (type == DUMP_UNRELOCATED) {
        res.notes += "; relocations reversed (unrelocated dump, preferred ImageBase restored)";
    } else {
        res.notes += "; relocations were applied in memory by the loader";
    }
    res.notes += "; debug directory repaired to AddressOfRawData form.";
    // v0.24: name the incomplete sections explicitly so a grep hitting
    // zeroed INIT/PAGE bytes can't be misread as "no data exists".
    for (const auto& s : res.sections) {
        if (!s.complete) {
            char tail[96];
            sprintf_s(tail, "; section %.8s partial: %llu/%llu bytes read",
                      s.name.c_str(),
                      (unsigned long long)s.dumped_bytes,
                      (unsigned long long)s.size);
            res.notes += tail;
        }
    }
    return res;
}

} // namespace suspex
