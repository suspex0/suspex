#pragma once

// v0.31 Phase 5 — rotating agent log + stdio safety for session-0 runs.
//
// Field report (rig): the agent ran via `cmd /c suspex_agent.exe --dev ...`
// under a scheduled task; after NIC churn the process stayed alive with the
// port LISTENING but every new SYN timed out — even loopback. Classic
// mechanism: under `cmd /c` in session 0, stdout/stderr are pipes nobody
// drains; gRPC logs connection errors to stderr during network churn, the
// pipe fills, and whichever thread is inside that blocked write (including
// event-engine / accept-path threads) stalls. Everything here exists to
// make that impossible: --log routes agent + gRPC diagnostics into a
// size-capped rotating file (stderr is spliced onto a drain pipe and
// relayed there), and service/task context redirects stdio to NUL so no
// code path can ever block on an undrained pipe.
//
// Deliberately standalone: no agent headers, also linked into umagent.

#include <cstddef>
#include <string>

namespace suspex::srvlog {

// Open the rotating log (append mode). max_bytes == 0 -> 4 MiB default.
// Fails soft: on error Logf() stays a no-op and Enabled() stays false.
void Open(const std::wstring& path, std::size_t max_bytes = 0);
void Close();
bool Enabled();

// One timestamped line into the log (and nowhere else). Thread-safe.
void Logf(const char* fmt, ...);

// Route all of gRPC's internal diagnostics into the rotating log.
// gRPC (and anything else in-process) logs to stderr; without capture
// those writes are the exact ones that wedged the rig — either an
// undrained session-0 pipe, or lost when stdio goes to NUL. This splices
// a drain pipe under stderr at both the CRT and SetStdHandle level and
// relays every line into the rotating file. Call after Open(); with no
// log open it is a no-op.
void CaptureStderr();

// Redirect stdout+stderr to NUL. For SCM/task context without --log:
// stdio there can be an undrained pipe, and a full pipe blocks the
// writer forever. Anything worth keeping must go through Logf() first.
// Console (--dev) runs keep their stdio.
void RedirectStdioToNul();

} // namespace suspex::srvlog
