cmake_minimum_required(VERSION 3.24)
project(suspex_driver C ASM_MASM)

set(SUSPEX_KMDF_VERSION "1.33" CACHE STRING "KMDF version to build against")

if(NOT SUSPEX_WDK_ROOT)
    foreach(candidate
            "$ENV{WindowsSdkDir}"
            "C:/Program Files (x86)/Windows Kits/10"
            "C:/Program Files/Windows Kits/10"
            "D:/Windows Kits/10")
        if(candidate AND EXISTS "${candidate}/Include")
            set(SUSPEX_WDK_ROOT "${candidate}" CACHE PATH "Windows Kits root")
            break()
        endif()
    endforeach()
endif()
if(NOT SUSPEX_WDK_ROOT)
    message(FATAL_ERROR "Windows Kits not found; install the WDK or set -DSUSPEX_WDK_ROOT=<path>")
endif()
message(STATUS "suspex_driver: WDK root ${SUSPEX_WDK_ROOT}")

file(GLOB SUSPEX_SDK_VERSIONS "${SUSPEX_WDK_ROOT}/Include/*")
set(SUSPEX_SDK_VERSION "")
foreach(v ${SUSPEX_SDK_VERSIONS})
    get_filename_component(name "${v}" NAME)
    if(EXISTS "${v}/km/ntddk.h" AND name MATCHES "^[0-9]")
        if(NOT SUSPEX_SDK_VERSION OR name GREATER SUSPEX_SDK_VERSION)
            set(SUSPEX_SDK_VERSION "${name}")
        endif()
    endif()
endforeach()
if(NOT SUSPEX_SDK_VERSION)
    message(FATAL_ERROR "No SDK with km headers found under ${SUSPEX_WDK_ROOT}/Include (WDK missing?)")
endif()
set(SUSPEX_KM_INC "${SUSPEX_WDK_ROOT}/Include/${SUSPEX_SDK_VERSION}/km")
set(SUSPEX_SHARED_INC "${SUSPEX_WDK_ROOT}/Include/${SUSPEX_SDK_VERSION}/shared")
set(SUSPEX_KM_LIB "${SUSPEX_WDK_ROOT}/Lib/${SUSPEX_SDK_VERSION}/km/x64")
set(SUSPEX_WDF_INC "${SUSPEX_WDK_ROOT}/Include/wdf/kmdf/${SUSPEX_KMDF_VERSION}")

function(suspex_find_wdf_lib name out)
    set(candidates
        "${SUSPEX_WDK_ROOT}/Lib/wdf/kmdf/x64/${SUSPEX_KMDF_VERSION}/${name}"
        "${SUSPEX_WDK_ROOT}/Lib/${SUSPEX_SDK_VERSION}/km/x64/${name}")
    foreach(c ${candidates})
        if(EXISTS "${c}")
            set(${out} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR
        "${name} not found. Searched:\n  ${candidates}\n"
        "The WDK install appears incomplete (KMDF ${SUSPEX_KMDF_VERSION} runtime libs missing). "
        "Re-run the WDK installer with the full 'Windows Driver Kit' feature or set SUSPEX_KMDF_VERSION to an installed version.")
endfunction()

# modern WDK KMDF link line (WindowsDriver.KernelMode.KMDF.props):
# ntoskrnl + hal + wmilib + WdfLdr.lib + WdfDriverEntry.lib (no wdf01000)
suspex_find_wdf_lib("wdfdriverentry.lib" SUSPEX_WDFDRIVERENTRY_LIB)
suspex_find_wdf_lib("wdfldr.lib" SUSPEX_WDFLDR_LIB)

set(SUSPEX_DRIVER_SOURCES
    src/DriverEntry.c
    src/Device.c
    src/Dispatcher.c
    src/dispatch_io.c
    src/dispatch_mem.c
    src/dispatch_proc.c
    src/dispatch_bp.c
    src/dispatch_kernel.c
    src/dispatch_watchdog.c
    src/dispatch_notify.c
    src/Memory.c
    src/Physical.c
    src/Context.c
    src/Processes.c
    src/BpList.c
    src/BpSw.c
    src/BpHw.c
    src/BpTrap.c
    src/BpTrapAsm.asm

    src/RemoteCall.c
    src/KernelCall.c
    src/Modules.c
    src/Vad.c
    src/Handles.c
    src/Pool.c
    src/Notify.c
    src/ObjDir.c
    src/Threads.c
    src/Idt.c
    src/Watchdog.c)

add_library(suspex_driver MODULE ${SUSPEX_DRIVER_SOURCES})
set_target_properties(suspex_driver PROPERTIES
    OUTPUT_NAME "suspex_driver"
    PREFIX ""
    SUFFIX ".sys")

target_include_directories(suspex_driver PRIVATE
    ${SUSPEX_KM_INC}
    ${SUSPEX_KM_INC}/crt
    ${SUSPEX_SHARED_INC}
    ${SUSPEX_WDF_INC}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(suspex_driver PRIVATE
    _AMD64_
    AMD64
    _WIN32_WINNT=0x0A00
    NTDDI_VERSION=0x0A00000B
    KMDF_VERSION_MAJOR=1
    KMDF_VERSION_MINOR=33
    POOL_NX_OPTIN=1)

if(MSVC)
    target_compile_options(suspex_driver PRIVATE
        /kernel /W4 /GS /Zp8 /GR- /EHs-c- /Oi /Z7 /FC /permissive- /volatile:metadata
        "$<$<CONFIG:Release>:/Ox>" "$<$<CONFIG:Release>:/Oy->")
    target_link_options(suspex_driver PRIVATE
        /SUBSYSTEM:NATIVE /ENTRY:FxDriverEntry /NODEFAULTLIB /DRIVER /MANIFEST:NO
        /INCREMENTAL:NO /MAP /DEBUG /MACHINE:X64 /INTEGRITYCHECK)
    target_link_directories(suspex_driver PRIVATE ${SUSPEX_KM_LIB})
    target_link_libraries(suspex_driver PRIVATE
        "${SUSPEX_WDFDRIVERENTRY_LIB}"
        "${SUSPEX_WDFLDR_LIB}"
        ntoskrnl.lib
        hal.lib
        wmilib.lib
        BufferOverflowK.lib
        ntstrsafe.lib)
endif()
