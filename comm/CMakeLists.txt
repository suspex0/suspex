cmake_minimum_required(VERSION 3.24)
project(suspex_comm CXX)

# Phase 7c: suspex_comm.cpp was split into per-concern TUs. The original
# suspex_comm.cpp stays as a facade holding the ABI compile-time guards;
# every function moved to a peer TU. suspex_comm.h is unchanged.
add_library(suspex_comm STATIC
    suspex_comm.cpp
    suspex_comm_core.cpp
    suspex_comm_mem.cpp
    suspex_comm_ctx.cpp
    suspex_comm_bp.cpp
    suspex_comm_watchdog.cpp
    suspex_comm_notify.cpp
    suspex_comm.h
    suspex_comm_internal.hpp
    suspex_abi.h)
target_include_directories(suspex_comm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(suspex_comm PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS UNICODE)
