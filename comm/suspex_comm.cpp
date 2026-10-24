// Facade TU for the split suspex_comm library.
//
// Phase 7c of the modular-split plan moved every function out of this file
// into per-concern TUs (suspex_comm_core / _mem / _ctx / _bp / _watchdog).
// What stays here is the ABI compile-time guards -- they belong to the
// library as a whole and this original path is the anchor callers see in
// build output. Callers keep including "suspex_comm.h" (unchanged) and
// linking against the same suspex_comm static target; no source-level or
// linker-visible name at the public boundary moved.
#include "suspex_comm.h"

#include <cstddef>
#include <cstdint>

namespace suspex {

// ABI guards: if any of these fire, suspex_abi.h drifted between driver and
// user-mode builds and the IOCTL surface is incompatible.
static_assert(sizeof(SUSPEX_PING_OUT) == 24, "ping out ABI");
static_assert(sizeof(SUSPEX_MEM_REQ) == 32, "mem req ABI (v2: Flags)");
static_assert(sizeof(SUSPEX_USER_ALLOC_IN) == 24, "alloc in ABI");
static_assert(sizeof(SUSPEX_USER_ALLOC_OUT) == 16, "alloc out ABI");
static_assert(sizeof(SUSPEX_MODULES_IN) == 24, "modules in ABI (v2: +Flags)");
static_assert(sizeof(SUSPEX_MODULE_ENTRY) == 16 + SUSPEX_MOD_NAME_CCH * 2 + SUSPEX_MOD_PATH_CCH * 2,
              "module entry ABI");
static_assert(offsetof(SUSPEX_MODULE_ENTRY, Name) == 16, "module entry layout");
static_assert(sizeof(SUSPEX_CTX_HDR_OUT) == 8 + SUSPEX_CONTEXT_SIZE, "ctx header ABI");
static_assert(sizeof(CONTEXT) == SUSPEX_CONTEXT_SIZE, "CONTEXT size vs ABI");
static_assert(sizeof(SUSPEX_BP_ENTRY) == 48, "bp entry ABI");
static_assert(offsetof(SUSPEX_BP_ENTRY, Address) == 32, "bp entry layout");
static_assert(sizeof(SUSPEX_REMOTE_CALL_IN) == 56, "remote call in ABI");
static_assert(sizeof(SUSPEX_REMOTE_CALL_OUT) == 16, "remote call out ABI");
static_assert(sizeof(SUSPEX_VAD_ENTRY) == 40, "vad entry ABI");
static_assert(sizeof(SUSPEX_HANDLE_ENTRY) == 32 + SUSPEX_HANDLE_TYPE_CCH * 2 + SUSPEX_HANDLE_NAME_CCH * 2,
              "handle entry ABI");
// v4 (2026-09-06): PHYS_RANGES + POOL_SCAN wire structs. If any of these fire,
// suspex_abi.h drifted after the v4 bump -- rebuild driver + comm + exerciser
// from the same suspex_abi.h and bump SUSPEX_ABI_VERSION if the layout was
// intentionally changed.
static_assert(sizeof(SUSPEX_PHYS_RANGE_ENTRY) == 24,
              "ABI v4 phys-range entry size (expect Base+Size+Kind+Reserved = 24)");
static_assert(offsetof(SUSPEX_PHYS_RANGE_ENTRY, Kind) == 16,
              "ABI v4 phys-range entry layout (Kind must follow Base+Size at offset 16)");
static_assert(sizeof(SUSPEX_PHYS_RANGES_HDR) == 16,
              "ABI v4 phys-ranges header size (expect Status+Count+Required+Reserved = 16)");
// v0.31 Phase 3.2: SUSPEX_POOL_SCAN_IN gained a Cursor UINT32 (7 UINT32s
// total) and the pattern/mask arrays grew from 16 B to 64 B. HDR gained
// Holes/SpanTruncated/LastIndex/NextCursor (8 UINT32s total).
static_assert(sizeof(SUSPEX_POOL_SCAN_IN) == 28 + SUSPEX_POOL_PATTERN_MAX * 2,
              "ABI v0.31 pool-scan input size (7*UINT32 + 2*Pattern[SUSPEX_POOL_PATTERN_MAX])");
static_assert(offsetof(SUSPEX_POOL_SCAN_IN, Pattern) == 24,
              "ABI v0.31 pool-scan input layout (Pattern must follow the first six UINT32 fields at offset 24; Cursor sits after Mask)");
static_assert(sizeof(SUSPEX_POOL_ENTRY) == 32,
              "ABI v4 pool entry size (expect VA+Size+Tag+NonPaged+MatchedOffset = 32)");
static_assert(offsetof(SUSPEX_POOL_ENTRY, MatchedOffset) == 24,
              "ABI v4 pool entry layout (MatchedOffset must sit at offset 24)");
static_assert(sizeof(SUSPEX_POOL_HDR) == 32,
              "ABI v0.31 pool header size (Status+Count+Required+Considered+Holes+SpanTruncated+LastIndex+NextCursor = 32)");

// ABI v7 (2026-09-09): no driver-side struct changes - the bump gates the new
// agent/comm surfaces (gRPC VaTranslate/Watch/LogTail/detached, agent_uptime_ms,
// RunExe.killed). These pins stay so a header drift can't silently re-enable or
// renumber the flag bits.
// ABI v8 (2026-09-10): watchdog IOCTL set + Files.LogFollow. Struct guards
// pinned below. (A brief v9 added Windows Sandbox RPCs; withdrawn
// 2026-09-14 — version returns to 8.)
// ABI v10 (2026-09-20): notify event ring (NOTIFY_SUBSCRIBE/READ/DISABLE/
// STATS) + OBJ_ENUM + THREAD_LIST IOCTLs. No changes to existing structs;
// the bump gates the new agent surfaces.
static_assert(SUSPEX_ABI_VERSION == 13,
              "ABI v13 expected (v12: ext mem-write hdr + write_path, VA_TRANSLATE cr3/pid, IDT_LIST; v13: KERNEL_CALL)");
static_assert(sizeof(SUSPEX_WDG_ARM_IN) == 24 + SUSPEX_WDG_MAX_LABEL,
              "ABI v8 watchdog arm-in size (5 fields + Label[32])");
static_assert(offsetof(SUSPEX_WDG_ARM_IN, Cookie) == 16,
              "ABI v8 watchdog arm-in layout (Cookie at offset 16)");
static_assert(offsetof(SUSPEX_WDG_ARM_IN, Label) == 24,
              "ABI v8 watchdog arm-in layout (Label at offset 24)");
static_assert(sizeof(SUSPEX_WDG_KICK_IN) == 16,
              "ABI v8 watchdog kick-in size (Id+DeadlineMs+Cookie)");
static_assert(sizeof(SUSPEX_WDG_KICK_OUT) == 32,
              "ABI v8 watchdog kick-out size (Status+Reserved+KickCount+LastKickUs+DeadlineUs)");
static_assert(sizeof(SUSPEX_WDG_LIST_HDR) == 24,
              "ABI v8 watchdog list header size (Status+Count+Required+Reserved+NowUs)");
static_assert(sizeof(SUSPEX_WDG_ENTRY) == 48 + SUSPEX_WDG_MAX_LABEL,
              "ABI v8 watchdog entry size (6 UINT64 + 2 UINT32 + Label[32])");
static_assert(SUSPEX_MEM_FLAG_ALLOW_SOFTFAULT == 0x1,
              "ABI v7 ALLOW_SOFTFAULT must stay bit 0");
static_assert(SUSPEX_MEM_FLAG_PARTIAL == 0x2,
              "ABI v7 PARTIAL must stay bit 1");
static_assert(SUSPEX_MEM_FLAG_ALLOW_MAP_WRITE == 0x4,
              "ABI v7 ALLOW_MAP_WRITE must stay bit 2");
static_assert(sizeof(SUSPEX_VA_TRANSLATE_IN) == 24,
              "ABI v12 va-translate input size (Va + Cr3 + Pid)");
static_assert(offsetof(SUSPEX_VA_TRANSLATE_IN, Cr3) == 8,
              "ABI v12 va-translate layout (Cr3 occupies the old Reserved[2] slot)");
static_assert(sizeof(SUSPEX_VA_TRANSLATE_OUT) == 24,
              "ABI v12 va-translate output size (Status+PageSizeShift+PhysicalAddress+Cr3)");
static_assert(offsetof(SUSPEX_VA_TRANSLATE_OUT, PhysicalAddress) == 8,
              "ABI v12 va-translate layout (PhysicalAddress must stay at offset 8 for v11 callers)");
// ABI v12 (2026-09-25): extended mem-write header (marker in the old
// Reserved slot), write out-reply, per-CPU IDT enumeration structs.
static_assert(sizeof(SUSPEX_MEM_WRITE_IN) == 48,
              "ABI v12 mem-write ext input (32B legacy prefix + Cr3 + Flags2 + Reserved)");
static_assert(offsetof(SUSPEX_MEM_WRITE_IN, Cr3) == 32,
              "ABI v12 mem-write layout (Cr3 must tail the legacy 32-byte header)");
static_assert(offsetof(SUSPEX_MEM_WRITE_IN, Flags) == 24,
              "ABI v12 mem-write layout (Flags must keep SUSPEX_MEM_REQ's offset)");
static_assert(sizeof(SUSPEX_MEM_WRITE_OUT) == 16,
              "ABI v12 mem-write output (Status + WritePath + Done)");
static_assert(sizeof(SUSPEX_IDT_LIST_IN) == 8,
              "ABI v12 idt-list input (AllCpus + Reserved)");
static_assert(sizeof(SUSPEX_IDT_ENTRY_ROW) == 48,
              "ABI v12 idt row (cpu/vector/handler/sel/ist/dpl/type/present/base)");
static_assert(sizeof(SUSPEX_IDT_LIST_HDR) == 24,
              "ABI v12 idt-list header (Status/Count/Required/IdtLimit/IdtBase)");

} // namespace suspex
