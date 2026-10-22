cmake_minimum_required(VERSION 3.24)
project(suspex0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# static CRT everywhere: matches the vcpkg static triplets
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(SUSPEX_BUILD_DRIVER "Build suspex_driver.sys (requires WDK)" ON)

# build version stamp: git sha + dirty flag baked into agent_version so a
# deployed binary reports which commit it came from (update_target.py checks)
find_package(Git QUIET)
set(SUSPEX_GIT_SHA "nogit")
set(SUSPEX_GIT_DIRTY "")
if(GIT_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE SUSPEX_GIT_SHA OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE _suspex_git_dirty OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(_suspex_git_dirty)
        set(SUSPEX_GIT_DIRTY "-dirty")
    endif()
endif()
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/build_version.h @ONLY)

# C++ gRPC stubs from proto/suspex.proto via vcpkg protoc + grpc_cpp_plugin
find_package(protobuf CONFIG QUIET)
find_package(gRPC CONFIG QUIET)
if(protobuf_FOUND AND gRPC_FOUND)
    set(SUSPEX_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
    set(SUSPEX_PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto_gen)
    file(MAKE_DIRECTORY ${SUSPEX_PROTO_GEN_DIR})

    get_target_property(protoc_executable protobuf::protoc IMPORTED_LOCATION_RELEASE)
    if(NOT protoc_executable)
        get_target_property(protoc_executable protobuf::protoc IMPORTED_LOCATION)
    endif()
    find_program(grpc_cpp_plugin_executable grpc_cpp_plugin HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/grpc" REQUIRED)

    set(SUSPEX_PROTO_SRCS "${SUSPEX_PROTO_GEN_DIR}/suspex.pb.cc" "${SUSPEX_PROTO_GEN_DIR}/suspex.grpc.pb.cc")
    set(SUSPEX_PROTO_HDRS "${SUSPEX_PROTO_GEN_DIR}/suspex.pb.h" "${SUSPEX_PROTO_GEN_DIR}/suspex.grpc.pb.h")

    add_custom_command(
        OUTPUT ${SUSPEX_PROTO_SRCS} ${SUSPEX_PROTO_HDRS}
        COMMAND ${CMAKE_COMMAND} -E echo "Generating C++ gRPC stubs from suspex.proto"
        COMMAND ${protoc_executable}
                --grpc_out=${SUSPEX_PROTO_GEN_DIR}
                --cpp_out=${SUSPEX_PROTO_GEN_DIR}
                -I ${SUSPEX_PROTO_DIR}
                --plugin=protoc-gen-grpc=${grpc_cpp_plugin_executable}
                ${SUSPEX_PROTO_DIR}/suspex.proto
        DEPENDS ${SUSPEX_PROTO_DIR}/suspex.proto
        USES_TERMINAL)
    set_source_files_properties(${SUSPEX_PROTO_SRCS} PROPERTIES GENERATED TRUE)
    add_custom_target(suspex_proto_gen ALL DEPENDS ${SUSPEX_PROTO_SRCS})
else()
    message(STATUS "gRPC/protobuf not found: agent target will be skipped (run vcpkg install grpc:x64-windows-static)")
endif()

if(SUSPEX_BUILD_DRIVER)
    add_subdirectory(driver)
endif()
add_subdirectory(comm)
add_subdirectory(tools)
add_subdirectory(mapper)
if(protobuf_FOUND AND gRPC_FOUND)
    add_subdirectory(agent)
    add_subdirectory(umagent)
endif()
