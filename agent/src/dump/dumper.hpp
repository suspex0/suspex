#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace suspex {

// reconstructs a file-layout PE from a target process's mapped image.
// sections stay at their VA offsets (classic VA dump); PointerToRawData is
// set to the aligned VirtualAddress so file/VA layouts coincide. The debug
// directory is repaired so the CodeView RSDS blob is reachable via
// AddressOfRawData and IDA can pick up PDBs for the dump.
class ModuleDumper {
public:
    enum DumpType {
        DUMP_AS_LOADED = 0,   // runtime image: IAT resolved, relocs applied
        DUMP_UNRELOCATED = 1, // reverse loader relocations, restore preferred ImageBase
    };

    struct SectionInfo {
        std::string name;
        UINT64 va = 0;          // section RVA within the image
        UINT64 size = 0;        // virtual size
        UINT64 dumped_bytes = 0; // bytes actually read; tail reads as zeros
        bool complete = false;
    };

    struct Result {
        std::string error;
        std::string notes;
        std::string sha256;
        std::vector<BYTE> image;
        std::vector<SectionInfo> sections; // v0.24: per-section residency map
        UINT64 base = 0;
        UINT64 sizeOfImage = 0;
    };

    using Reader = bool (*)(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len);
    static Result Dump(void* readerCtx, Reader reader, UINT32 pid, UINT64 base,
                       DumpType type = DUMP_AS_LOADED);
};

} // namespace suspex
