#pragma once

// Pure-Win32 remote-thread function call shared by the agent and the
// umagent (no comm/driver/umem linkage). CALL_USER delivery: a two-page
// block (params on page 0 = RW, position-independent trampoline on page 1
// = RX — page-granular VirtualProtectEx requires the split) is injected
// into pid with a remote thread; the stub calls Target with
// Args[0..3] in rcx/rdx/r8/r9 and Args[4..15] on the stack (ms64), then
// records rax + TEB LastErrorValue + a Done marker.
//
// Contract:
//   * x64 targets only; WOW64 pids are refused (the stub is x64 code).
//   * No SEH in the stub: an unhandled callee exception TERMINATES THE
//     WHOLE PROCESS (WerFault) — the crashed thread's exit code still
//     carries the NTSTATUS, detected by the 0xC0000000 range check.
//     Only call functions known not to fault.
//   * On timeout the thread is deliberately left running (inspect via the
//     returned tid + stub_va; free the page with mem_rw free afterwards)
//     unless kill_on_timeout opts into TerminateThread + free.
//   * Pointer args are caller-marshalled: allocate in the target via
//     Memory.Alloc (+Write) and pass the VA in Args.
//   * rax is the only return captured; rdx:rax / floating returns are out
//     of scope.

#include <cstdint>
#include <string>
#include <vector>

namespace suspex {

struct CallParams {                 // all little-endian, naturally packed
    std::uint64_t Magic;            // 0x00 — sanity tag (write+readback verify)
    std::uint64_t Target;           // 0x08
    std::uint32_t Argc;             // 0x10 (0..16)
    std::uint32_t Flags;            // 0x14
    std::uint64_t Ret;              // 0x18 — stub writes rax
    std::uint32_t LastError;        // 0x20 — stub writes gs:[0x68] (TEB64 LastErrorValue)
    std::uint32_t Done;             // 0x24 — stub writes 1 after Ret/LastError
    std::uint64_t Args[16];         // 0x28
};
static_assert(sizeof(CallParams) == 0xA8, "CallParams layout");

constexpr std::uint32_t CALL_STUB_OFFSET = 0x1000;  // stub VA = page + 0x1000
constexpr std::uint32_t CALL_STUB_SIZE = 0x1000;    // stub occupies page 1
constexpr std::uint32_t CALL_ALLOC_SIZE = 0x2000;   // params page + stub page
constexpr std::uint64_t CALL_PARAMS_MAGIC = 0x5350434C4C424C4BULL; // 'KBLLCLPS'

struct CallUserResult {
    bool ok = false;           // transport level: the mechanism ran
    std::string error;         // why ok=false (argc, open, alloc, ...)
    std::uint64_t ret = 0;     // rax
    std::uint32_t last_error = 0;
    std::uint32_t done = 0;    // stub completed marker (1 = wrote Ret/LastError)
    std::uint64_t magic_back = 0;
    bool timed_out = false;
    bool exception = false;    // exit code in NTSTATUS error range
    std::uint64_t exit_code = 0;
    std::uint32_t tid = 0;
    std::uint64_t stub_va = 0; // param+stub page (cleanup on timeout)
    bool killed = false;       // kill_on_timeout path actually terminated
};

CallUserResult CallUser(std::uint32_t pid, std::uint64_t target,
                        const std::vector<std::uint64_t>& args,
                        std::uint32_t timeout_ms, bool kill_on_timeout);

} // namespace suspex