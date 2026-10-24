#pragma once

// light on purpose: no generated gRPC headers here. They are included as the
// FIRST header of each translation unit in services*.cpp — generated grpcpp
// headers must be parsed before windows.h, whose macros otherwise leak into
// the generated declarations (WriteConsole/ReadConsole/...).

#include "../config.hpp"
#include "../driver_mgr.hpp"
#include "../exec.hpp"
#include "../events.hpp"
#include "../dbg/dbg_session.hpp"
#include "../host/net_pin.hpp"

#include <string>

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>

namespace google {
namespace protobuf {
class Message;
}
} // namespace google

namespace grpc {
class ServerBuilder;
class ServerContext;
}

namespace suspex {

grpc::Status CheckAuth(grpc::ServerContext* ctx, const std::string& token);
void FillStatus(google::protobuf::Message* msg, const std::string& err);

void RegisterCoreServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec, host::NetPinMgr& netPin);
void RegisterFileExecServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                              ExecMgr& exec);
void RegisterRegistryService(grpc::ServerBuilder& builder, const AgentConfig& cfg);
// v8: driver-backed wedge-detector; refuses cleanly when the driver is absent.
void RegisterWatchdogService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                             DriverMgr& drv);
// v11: Device.Ioctl (usermode actuator) + Telemetry (ETW query-only).
void RegisterDeviceServices(grpc::ServerBuilder& builder, const AgentConfig& cfg);
// v11: driver-backed notify event ring (the agent's "ears"); refuses
// cleanly when the driver is absent.
void RegisterEventsService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                           DriverMgr& drv);

inline void RegisterServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                             ExecMgr& exec, host::NetPinMgr& netPin)
{
    RegisterCoreServices(builder, cfg, drv, exec, netPin);
    RegisterFileExecServices(builder, cfg, drv, exec);
    RegisterRegistryService(builder, cfg);
    RegisterWatchdogService(builder, cfg, drv);
    RegisterDeviceServices(builder, cfg);
    RegisterEventsService(builder, cfg, drv);
}

// shared user-memory read: driver first, ReadProcessMemory fallback
struct MemReaderCtx {
    DriverMgr* drv = nullptr;
};
bool UserMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len);
// shared kernel-memory read: driver only, pid ignored
bool KernelMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len);

// module enumeration with driver-then-toolhelp fallback
bool ListUserModules(DriverMgr* drv, UINT32 pid, std::vector<suspex::ModuleEntry>* out);

// case-insensitive basename-or-full-path module lookup (see DumpModule in
// services2.cpp for the reference pattern); returns 0 when not found
std::string BasenameLower(const std::string& p);
UINT64 FindModuleBase(const std::vector<suspex::ModuleEntry>& mods,
                      const std::string& want);
std::string FindOwningModule(const std::vector<suspex::ModuleEntry>& mods, UINT64 addr);

} // namespace suspex
