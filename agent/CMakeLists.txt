cmake_minimum_required(VERSION 3.24)
project(suspex_agent CXX)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

set(SUSPEX_AGENT_SOURCES
    src/main.cpp
    src/breadcrumb.cpp
    src/config.cpp
    src/driver_mgr.cpp
    src/exec.cpp
    src/files.cpp
    src/listen_watch.cpp
    src/log_ring.cpp
    src/srv_log.cpp
    src/watch.cpp
    src/exec/detached.cpp
    src/exec/call_user.cpp
    src/dbg/dbg_engine.cpp
    src/dbg/dbg_process.cpp
    src/dbg/dbg_state.cpp
    src/dbg/dbg_mem.cpp
    src/dbg/dbg_bp.cpp
    src/dbg/dbg_exec.cpp
    src/dump/dumper.cpp
    src/host/host_info.cpp
    src/host/net_pin.cpp
    src/host/capture_dxgi.cpp
    src/host/capture_wgc.cpp
    src/host/window_enum.cpp
    src/host/screen_dispatch.cpp
    src/host/screen_worker.cpp
    src/pe/pe_reader.cpp
    src/pe/heap_walker.cpp
    src/service/service_main.cpp
    src/grpc/services.cpp
    src/grpc/services_common.cpp
    src/grpc/services_agent.cpp
    src/grpc/services_memory.cpp
    src/grpc/services_debug.cpp
    src/grpc/services_bp.cpp
    src/grpc/services2.cpp
    src/grpc/services_files.cpp
    src/grpc/services_exec.cpp
    src/grpc/services_registry.cpp
    src/grpc/services_watchdog.cpp
    src/grpc/services_device.cpp
    src/grpc/services_events.cpp
    ${SUSPEX_PROTO_SRCS}
    ${SUSPEX_PROTO_HDRS})

add_executable(suspex_agent ${SUSPEX_AGENT_SOURCES})
add_dependencies(suspex_agent suspex_proto_gen)
target_include_directories(suspex_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${SUSPEX_PROTO_GEN_DIR}
    ${CMAKE_BINARY_DIR}/generated
    ${CMAKE_SOURCE_DIR}/comm
    # plain /I, not /external:I: external treatment of the vcpkg grpcpp
    # headers broke codegen visibility on this toolchain
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
target_compile_definitions(suspex_agent PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
# /Z7 instead of /Zi: parallel TUs sharing one .pdb deadlock on exFAT volumes
target_compile_options(suspex_agent PRIVATE /Z7)
target_link_libraries(suspex_agent PRIVATE
    suspex_comm
    gRPC::grpc++
    protobuf::libprotobuf
    ole32
    advapi32
    shell32
    userenv
    ntdll
    # v1.0.1 Phase 2.2/5: net_pin adapter APIs + listener self-test
    iphlpapi
    ws2_32
    # v15 screen capture / window telemetry
    user32
    gdi32
    psapi
    d3d11
    dxgi
    dwmapi
    wtsapi32
    windowscodecs
    windowsapp)
