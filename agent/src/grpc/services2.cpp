// Facade for the FilesSvc / ExecSvc pair. The class bodies live in
// services_files.cpp and services_exec.cpp — this TU just wires their
// singletons into the gRPC ServerBuilder under the same public entry
// point (`RegisterFileExecServices`) that services.hpp declares.

#include <grpcpp/grpcpp.h>
#include "suspex.grpc.pb.h"

#include "services.hpp"

namespace suspex {

// Internal wiring exported by the two sibling TUs. Kept in this file to
// avoid a header rewrite; ABI is unchanged because `RegisterFileExecServices`
// remains the only externally-consumed symbol.
void RegisterFilesSvcInto(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec);
void RegisterExecSvcInto(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                         ExecMgr& exec);

void RegisterFileExecServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                              ExecMgr& exec)
{
    RegisterFilesSvcInto(builder, cfg, drv, exec);
    RegisterExecSvcInto(builder, cfg, drv, exec);
}

} // namespace suspex
