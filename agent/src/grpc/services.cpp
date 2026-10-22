// Phase 6a: this translation unit is now a facade / marker.
//
// The 2000+ lines that used to live here were split into five sibling TUs
// (mechanical-only, no ABI or semantic changes):
//
//   services_common.cpp  — CheckAuth, FillStatus, the shared user/kernel
//                          memory readers, the module-lookup helpers and
//                          the RegisterCoreServices fan-out.
//   services_agent.cpp   — AgentSvc (Status, DriverLoad/Unload, SelfUpdate,
//                          RecentOps, HostInfo) + RegisterAgentSvc.
//   services_memory.cpp  — MemorySvc (Read/Write/Alloc/Free/Protect, module
//                          walk, VAD/Handle/Phys enum, pattern scan,
//                          VaTranslate, Watch) + RegisterMemorySvc.
//   services_debug.cpp   — DebugSvc (Launch/Attach/Detach/Continue/Step,
//                          register + stack + region access, event stream)
//                          + RegisterDebugSvc.
//   services_bp.cpp      — BpSvc (Add/Remove/List/SetEnabled) +
//                          RegisterBpSvc.
//
// Every public symbol callers used to reach through <src/grpc/services.hpp>
// (RegisterCoreServices, RegisterServices, CheckAuth, FillStatus,
// UserMemReadFn, KernelMemReadFn, ListUserModules, BasenameLower,
// FindModuleBase, FindOwningModule) still resolves — it just lands in one
// of the new TUs above. This file stays in the build so anyone chasing a
// blame trail lands here first.

// Intentionally empty: content lives in services_{common,agent,memory,
// debug,bp}.cpp. Keeping the file avoids CMake churn for downstream forks
// that pinned the original path; if you drop it, remove the matching entry
// from agent/CMakeLists.txt as well.
