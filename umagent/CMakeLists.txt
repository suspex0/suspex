cmake_minimum_required(VERSION 3.24)
project(suspex_umagent CXX)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

set(SUSPEX_UMAGENT_SOURCES
    src/main.cpp
    src/umem.cpp
    src/um_services.cpp
    ${SUSPEX_PROTO_SRCS}
    ${SUSPEX_PROTO_HDRS}
    # build-independent PE walker shared with the agent (imports/exports)
    ../agent/src/pe/pe_reader.cpp
    # shared param-block trampoline call (CALL_USER) — same TU as the agent
    ../agent/src/exec/call_user.cpp
    # v0.31 Phase 5: shared rotating log + listener self-test
    ../agent/src/srv_log.cpp
    ../agent/src/listen_watch.cpp)

add_executable(suspex_umagent ${SUSPEX_UMAGENT_SOURCES})
add_dependencies(suspex_umagent suspex_proto_gen)
target_include_directories(suspex_umagent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/pe
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/exec
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${SUSPEX_PROTO_GEN_DIR}
    ${CMAKE_BINARY_DIR}/generated
    # plain /I, not /external:I: external treatment of the vcpkg grpcpp
    # headers broke codegen visibility on this toolchain (same as agent)
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
target_compile_definitions(suspex_umagent PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
# /Z7 instead of /Zi: parallel TUs sharing one .pdb deadlock on exFAT volumes
target_compile_options(suspex_umagent PRIVATE /Z7)
target_link_libraries(suspex_umagent PRIVATE
    gRPC::grpc++
    protobuf::libprotobuf
    advapi32
    # v0.31 Phase 5: listener self-test loopback probes
    ws2_32)
