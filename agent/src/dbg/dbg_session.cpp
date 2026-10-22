// dbg_session.cpp - TU-level split (Phase 6c, 2026-09-17 modular-split plan).
// The DbgSession implementation moved to sibling TUs; this file is retained as
// a facade marker so tools/scripts that reference the original path still find
// it. Public interface (dbg_session.hpp) is unchanged.
//
//   dbg_engine.cpp  - InitEngine, RunOnEngine, Shutdown, EngineLoop,
//                     HandleEventLocked, SysTidFromEngineIdLocked, Instance
//   dbg_process.cpp - Launch, Attach, Detach, Continue, Step
//   dbg_state.cpp   - GetRegs, SetRegs, GetThreads, Stacktrace
//   dbg_mem.cpp     - ReadMem, WriteMem, Regions
//   dbg_bp.cpp      - BpAdd, FindBpLocked, BpRemove, BpList, BpSetEnabled
//   dbg_exec.cpp    - DbgOutputSink, Execute
