#pragma once

// Internal, per-service registration factories.
//
// Phase 6a TU split of services.cpp moved each service class (AgentSvc,
// MemorySvc, DebugSvc, BpSvc) into its own translation unit. Each of those
// TUs defines a tiny factory that constructs the (static local) service
// object and hands it to the passed-in ServerBuilder. services_common.cpp
// calls the four factories from RegisterCoreServices.
//
// Kept out of the public services.hpp so no caller outside src/grpc/ sees
// these — the public interface (RegisterCoreServices / RegisterServices)
// is unchanged.

#include <grpcpp/grpcpp.h>

#include "../config.hpp"
#include "../driver_mgr.hpp"

namespace suspex {

void RegisterAgentSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv);
void RegisterMemorySvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv);
void RegisterDebugSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv);
void RegisterBpSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv);

} // namespace suspex
