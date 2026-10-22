#pragma once

#include <string>

namespace suspex {

struct AgentConfig {
    int port = 50074;
    std::string token;             // required
    std::wstring driverPath;       // default: <exedir>\suspex_driver.sys
    std::wstring mapperPath;       // default: <exedir>\mapper.exe
    std::wstring trashDir;         // default: <exedir>\.suspex_trash
    bool allowDriverLoad = true;
    bool allowDriverUnload = true;
    bool allowDelete = false;      // hard delete; default move-to-trash
    size_t maxTransferBytes = 512ull * 1024 * 1024;
    size_t maxMemReadBytes = 8ull * 1024 * 1024;

    static AgentConfig FromArgs(int argc, char** argv);
    static std::wstring ExeDir();
};

} // namespace suspex
