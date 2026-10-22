cmake_minimum_required(VERSION 3.24)
project(suspex_tools CXX)

add_executable(drv_exerciser
    drv_exerciser.cpp
    cmd_mem.cpp
    cmd_ctx.cpp
    cmd_bp.cpp
    cmd_watchdog.cpp
    cmd_call.cpp
)
target_link_libraries(drv_exerciser PRIVATE suspex_comm)
