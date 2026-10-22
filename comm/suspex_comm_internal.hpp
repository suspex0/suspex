// Internal shared helpers for the split suspex_comm translation units.
// Not part of the public API — suspex_comm.h stays unchanged for callers.
//
// The single suspex_comm.cpp was split (Phase 7c of the modular-split plan)
// into five TUs by concern: core, mem, ctx, bp, watchdog. Symbols that used
// to have file-local (static) linkage inside suspex_comm.cpp are declared
// here so the peer TUs can share the single definition (IoctlFor lives in
// suspex_comm_core.cpp) without duplicating it or re-#defining the same
// NTSTATUS constants in every file.
#pragma once

#include "suspex_comm.h"

namespace suspex {

// NTSTATUS codes the driver may return through the standard *_HDR.Status
// slot. Kept as macros to match the original suspex_comm.cpp exactly.
#define SUSPEX_STATUS_BUFFER_OVERFLOW ((UINT32)0x80000005L)
#define SUSPEX_STATUS_PARTIAL_COPY ((UINT32)0x8000000DL)
// NTSTATUS usermode winnt.h doesn't give us — v12 comm-side failures.
#define SUSPEX_STATUS_INFO_LENGTH_MISMATCH ((UINT32)0xC0000004L)
#define SUSPEX_STATUS_NOT_SUPPORTED ((UINT32)0xC00000BBL)

// Space -> IOCTL dispatch helper. Was a `static` function inside
// suspex_comm.cpp; now has external linkage within the static library so
// suspex_comm_mem.cpp (the only caller besides tests) can share it with
// the definition kept in suspex_comm_core.cpp. Not exposed via any public
// header, so no ABI change.
ULONG IoctlFor(Space s, ULONG user, ULONG kernel, ULONG phys);

} // namespace suspex
