#pragma once

#include <string>

namespace suspex {

// returns process exit code; runs fn as a Windows service when SCM started us
int RunAsServiceOrConsole(bool console, const std::string& serviceName,
                          int (*fn)(int, char**), int argc, char** argv);

} // namespace suspex
