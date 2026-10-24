#pragma once

// light on purpose: no generated gRPC headers here (same rule as the agent's
// services.hpp — they are included as the FIRST headers of um_services.cpp).

#include <cstdint>
#include <string>

#include "build_version.h"

namespace google {
namespace protobuf {
class Message;
}
} // namespace google

namespace grpc {
class ServerBuilder;
class ServerContext;
class Status;
}

namespace um {

struct Config {
    std::string bind = "127.0.0.1"; // localhost-only by default: same-host parity view
    int port = 50075;
    std::string token;
    std::string version = "1.0.1+" SUSPEX_GIT_SHA SUSPEX_GIT_DIRTY;
    uint64_t maxReadBytes = 8ull << 20;
};

void FillStatus(google::protobuf::Message* msg, const std::string& err);

void RegisterServices(grpc::ServerBuilder& builder, const Config& cfg);

} // namespace um
