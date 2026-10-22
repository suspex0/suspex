#pragma once

// Build-independent PE walker: takes a `ReadFn` callable so the caller
// controls the memory backing (user-mode via ReadProcessMemory / driver
// fallback, kernel-mode via driver MemRead, or a raw file). All offsets
// are validated against `size_of_image` before dereference so a malformed
// image can't drive us into a bad read.
//
// Portions adapted from ReverseKit (MIT), zer0condition/ReverseKit
//   ReverseKit/Imports/Imports.cpp

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace suspex::pe {

using ReadFn = std::function<bool(uint64_t addr, void* dst, size_t len)>;

struct IatRow {
    std::string dll;
    std::string name;      // empty when imported by ordinal
    uint32_t ordinal;      // valid iff name.empty()
    uint64_t iat_slot;     // VA of the FirstThunk slot in the caller image
    uint64_t resolved;     // value currently in the slot
};

struct ExpRow {
    std::string name;      // empty for pure ordinal exports
    std::string forwarder; // "dll.name" or "dll.#ord" when the RVA lands in the export dir
    uint32_t ordinal;
    uint64_t rva;
};

// Both parsers pull PE headers via `read` and return true on success.
// A malformed image or an unreadable header yields false with `out` untouched.
bool ParseImports(uint64_t module_base, ReadFn read, std::vector<IatRow>& out,
                  std::string* err = nullptr);
bool ParseExports(uint64_t module_base, ReadFn read, std::vector<ExpRow>& out,
                  std::string* err = nullptr);

} // namespace suspex::pe
