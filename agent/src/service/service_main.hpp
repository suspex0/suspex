#pragma once

#include <functional>
#include <string>

namespace suspex {

// returns process exit code; runs fn as a Windows service when SCM started us
int RunAsServiceOrConsole(bool console, const std::string& serviceName,
                          int (*fn)(int, char**), int argc, char** argv);

// v0.31 Phase 5: let the agent unwind gracefully when SCM sends STOP.
// The hook runs on the SCM handler thread and should make AgentMain's
// server Wait() return and the process exit on its own (the worker thread
// then reports SERVICE_STOPPED after fn returns). Pass nullptr to clear.
// The handler falls back to ExitProcess after a grace period if the hook
// does not produce an exit in time.
void SetServiceStopHook(std::function<void()> hook);

} // namespace suspex
