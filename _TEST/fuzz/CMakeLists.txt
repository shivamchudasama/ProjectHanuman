# SPDX-License-Identifier: MIT
#
# libFuzzer targets for the code that parses bytes from outside the device
# (BLE peers, the CAN bus, files on the flash). Separate from the unit tests:
# it needs clang with -fsanitize=fuzzer.
#
#   cmake -G Ninja -S _TEST/fuzz -B build_fuzz -DCMAKE_C_COMPILER=clang
#   cmake --build build_fuzz
#   build_fuzz/fuzz_setu_rx build_fuzz/corpus/setu_rx -max_total_time=60
#
# Seed corpora come from vectors/wire.json (tools/gen_fuzz_corpus.py).

cmake_minimum_required(VERSION 3.20)
# libFuzzer links the static C runtime on Windows; everything must match it
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
project(ProjectHanuman_Fuzz C)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
   message(FATAL_ERROR "The fuzz targets need clang (libFuzzer)")
endif()

set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(REPO_ROOT ${TEST_DIR}/..)
set(SHIM_DIR ${TEST_DIR}/shim)
set(ASW_DIR ${REPO_ROOT}/_ASW)
set(LIB_DIR ${REPO_ROOT}/_LIB)
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)

find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

include(FetchContent)
FetchContent_Declare(unity
   URL https://github.com/ThrowTheSwitch/Unity/archive/refs/tags/v2.6.1.tar.gz
   URL_HASH SHA256=b41a66d45a6b99758fb3202ace6178177014d52fc524bf1f72687d93e9867292
   SOURCE_SUBDIR _no_cmake_
   DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(unity)

set(FUZZ_FLAGS -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
   -fno-omit-frame-pointer -std=gnu99 -Wno-unused-function -Wno-unused-variable)
if(WIN32)
   # The MSVC runtime has no UBSan runtime for the fuzzer link; ASan + libFuzzer
   set(FUZZ_FLAGS -g -O1 -fsanitize=fuzzer,address -fno-omit-frame-pointer -std=gnu99
      -Wno-unused-function -Wno-unused-variable -D_CRT_SECURE_NO_WARNINGS
      -include ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_win.h)
endif()

# Unity and the shim runtime, instrumented for coverage but without the fuzzer main
string(REPLACE "fuzzer," "fuzzer-no-link," LIB_FLAGS "${FUZZ_FLAGS}")
add_library(unity STATIC ${unity_SOURCE_DIR}/src/unity.c)
target_include_directories(unity PUBLIC ${unity_SOURCE_DIR}/src)
target_compile_options(unity PRIVATE ${LIB_FLAGS})
add_library(zephyr_sim STATIC ${SHIM_DIR}/zephyr_sim.c)
target_include_directories(zephyr_sim PUBLIC ${SHIM_DIR})
target_compile_options(zephyr_sim PRIVATE ${LIB_FLAGS})

# Golden wire vectors, as for the unit tests (the reused test files include them)
add_custom_command(
   OUTPUT ${GEN_DIR}/wire_vectors.h
   COMMAND Python3::Interpreter ${TEST_DIR}/tools/gen_vectors.py
      ${TEST_DIR}/vectors/wire.json ${REPO_ROOT} ${GEN_DIR}/wire_vectors.h
   DEPENDS ${TEST_DIR}/vectors/wire.json ${TEST_DIR}/tools/gen_vectors.py ${REPO_ROOT}/AA00000100.hex
   COMMENT "Generating wire_vectors.h")
add_custom_target(wire_vectors DEPENDS ${GEN_DIR}/wire_vectors.h)

# add_fuzz_target(<name> SOURCES ... [INCLUDES ...] [DEFINES ...])
function(add_fuzz_target NAME)
   cmake_parse_arguments(T "" "" "SOURCES;INCLUDES;DEFINES" ${ARGN})
   add_executable(${NAME} ${T_SOURCES})
   target_include_directories(${NAME} PRIVATE ${SHIM_DIR} ${GEN_DIR} ${T_INCLUDES})
   target_compile_definitions(${NAME} PRIVATE ${T_DEFINES})
   target_compile_options(${NAME} PRIVATE ${FUZZ_FLAGS})
   target_link_options(${NAME} PRIVATE ${FUZZ_FLAGS})
   target_link_libraries(${NAME} PRIVATE unity zephyr_sim)
   add_dependencies(${NAME} wire_vectors)
endfunction()

set(SETU_DIR ${LIB_DIR}/SETU)
set(FSMGR_DIR ${LIB_DIR}/FileSysManager)
set(SETU_INCLUDES ${SETU_DIR} ${ASW_DIR}/_BLE_GENERIX ${TEST_DIR}/unit/SETU)
set(DS_INCLUDES ${ASW_DIR}/_DATA_STORE ${ASW_DIR}/_SETU_SVC ${FSMGR_DIR} ${SETU_INCLUDES})

# SETU Server + router + DataStore + File System Manager, frames from a BLE peer
add_fuzz_target(fuzz_setu_rx
   SOURCES fuzz_setu_rx.c ${SETU_DIR}/SETU_Frame.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${DS_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT SETU_ENABLE_CLIENT=0)

# File commands: router + FsCmd + File System Manager (stubs of test_fscmd.c)
add_fuzz_target(fuzz_fscmd
   SOURCES fuzz_fscmd.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${ASW_DIR}/_FS_CMD ${DS_INCLUDES}
   DEFINES CONFIG_FS_CMD=1)

# UDS over BLE: router + UdsCmd, UdsJob recorded (stubs of test_uds_cmd.c)
set(UDS_INCLUDES ${ASW_DIR}/_UDS ${ASW_DIR}/_CAN ${ASW_DIR}/_DATA_STORE ${FSMGR_DIR}
   ${LIB_DIR}/UdsClient ${TEST_DIR}/unit/UdsClient)
add_fuzz_target(fuzz_uds_cmd
   SOURCES fuzz_uds_cmd.c
   INCLUDES ${UDS_INCLUDES} ${ASW_DIR}/_SETU_SVC ${SETU_INCLUDES}
   DEFINES CONFIG_UDS_CMD=1)

# UDS flash job on a fuzzed file (stubs, ECU and helpers of test_uds_job.c)
add_fuzz_target(fuzz_uds_job
   SOURCES fuzz_uds_job.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${UDS_INCLUDES})

# Host authentication: what an untrusted host sends, and the link events
# (stubs of test_host_auth.c)
add_fuzz_target(fuzz_host_auth
   SOURCES fuzz_host_auth.c
   INCLUDES ${ASW_DIR}/_HOST_AUTH ${ASW_DIR}/_PROV ${ASW_DIR}/_SETU_SVC ${ASW_DIR}/_CSR
      ${ASW_DIR}/_DEVICE_CERT ${TEST_DIR}/shim/psa_stub ${SETU_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# UDS client: ECU responses off the CAN bus, scripted transport (sim_uds_tp.h)
add_fuzz_target(fuzz_uds_client
   SOURCES fuzz_uds_client.c
   INCLUDES ${LIB_DIR}/UdsClient ${TEST_DIR}/unit/UdsClient)
