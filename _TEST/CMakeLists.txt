# SPDX-License-Identifier: MIT
#
# Host test project: builds the libraries in _LIB and the testable application
# modules in _ASW for the PC, against the Zephyr shim in shim/, with Unity.
#
#   cmake -S _TEST -B build_test [-DSANITIZE=ON] [-DCOVERAGE=ON]
#   cmake --build build_test
#   ctest --test-dir build_test --output-on-failure
#
# Every test writes JUnit XML to build_test/report/junit/<test>.xml.

cmake_minimum_required(VERSION 3.20)
project(ProjectHanuman_HostTests C)
enable_testing()

option(SANITIZE "Build with AddressSanitizer and UBSan (gcc/clang, Linux/macOS)" OFF)
option(COVERAGE "Build with gcov instrumentation (for gcovr)" OFF)

set(REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(SHIM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/shim)
set(PSA_STUB_DIR ${SHIM_DIR}/psa_stub)           # stubbed PSA Crypto (most tests)
set(TFPSA_SHIM_DIR ${SHIM_DIR}/tfpsa)            # host platform for the real TF-PSA-Crypto
set(TOOLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tools)
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
set(REPORT_DIR ${CMAKE_CURRENT_BINARY_DIR}/report)
file(MAKE_DIRECTORY ${REPORT_DIR}/junit)

find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

# ---- Unity (only src/unity.c is used; its own CMakeLists is skipped) ---------
include(FetchContent)
FetchContent_Declare(unity
   URL https://github.com/ThrowTheSwitch/Unity/archive/refs/tags/v2.6.1.tar.gz
   URL_HASH SHA256=b41a66d45a6b99758fb3202ace6178177014d52fc524bf1f72687d93e9867292
   SOURCE_SUBDIR _no_cmake_
   DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(unity)
add_library(unity STATIC ${unity_SOURCE_DIR}/src/unity.c)
target_include_directories(unity PUBLIC ${unity_SOURCE_DIR}/src)

# ---- Mbed TLS 4 / TF-PSA-Crypto (the major version NCS v3.4.1 ships) ----------
# Only test_devicecert_verify links it: the device's X.509 verification runs
# against the real library. Static libraries, no programs or tests of its own;
# shim/tfpsa/tf_psa_crypto_host_config.h trims what the host cannot provide.
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE ${TFPSA_SHIM_DIR}/tf_psa_crypto_host_config.h CACHE FILEPATH "" FORCE)
FetchContent_Declare(mbedtls
   URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.1/mbedtls-4.1.1.tar.bz2
   URL_HASH SHA256=3359a349e23db3d5536fcee032ae7b2ecbfc08972fab643089b5cbf2a375c98c
   DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

# ---- Compiler options for everything below -----------------------------------
set(TEST_C_FLAGS -std=gnu99 -Wall -Wextra -Werror -Wno-missing-field-initializers)
if(SANITIZE)
   add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined
      -fno-omit-frame-pointer)
   add_link_options(-fsanitize=address,undefined)
endif()
if(COVERAGE)
   add_compile_options(--coverage -O0)
   add_link_options(--coverage)
endif()

# After the options above, so the sanitizers also cover Mbed TLS
FetchContent_MakeAvailable(mbedtls)
# Its key storage includes the platform's ITS headers (shim/tfpsa/include)
target_include_directories(tfpsacrypto PRIVATE ${TFPSA_SHIM_DIR}/include)
# On Windows it links bcrypt for its OS entropy source, which the host config
# replaces (and old MinGW does not ship)
if(WIN32)
   get_target_property(TFPSA_LIBS tfpsacrypto INTERFACE_LINK_LIBRARIES)
   list(REMOVE_ITEM TFPSA_LIBS bcrypt)
   set_target_properties(tfpsacrypto PROPERTIES INTERFACE_LINK_LIBRARIES "${TFPSA_LIBS}")
endif()

# ---- Golden wire vectors (vectors/wire.json -> gen/wire_vectors.h) -----------
add_custom_command(
   OUTPUT ${GEN_DIR}/wire_vectors.h
   COMMAND Python3::Interpreter ${TOOLS_DIR}/gen_vectors.py
      ${CMAKE_CURRENT_SOURCE_DIR}/vectors/wire.json ${REPO_ROOT} ${GEN_DIR}/wire_vectors.h
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/vectors/wire.json ${TOOLS_DIR}/gen_vectors.py
      ${REPO_ROOT}/AA00000100.hex
   COMMENT "Generating wire_vectors.h")
add_custom_target(wire_vectors DEPENDS ${GEN_DIR}/wire_vectors.h)

# ---- Shim runtime (log capture, assert trap, thread runner) ------------------
add_library(zephyr_sim STATIC ${SHIM_DIR}/zephyr_sim.c)
target_include_directories(zephyr_sim PUBLIC ${SHIM_DIR})
target_compile_options(zephyr_sim PRIVATE ${TEST_C_FLAGS})

# add_unit_test(<name> SOURCES ... [INCLUDES ...] [DEFINES ...] [ARGS ...])
#   One Unity executable, registered with CTest through tools/run_unity.py.
function(add_unit_test NAME)
   cmake_parse_arguments(T "" "" "SOURCES;INCLUDES;DEFINES;ARGS" ${ARGN})
   add_executable(${NAME} ${T_SOURCES})
   # shim/ comes first so its zephyr/*.h and AppLog.h win
   target_include_directories(${NAME} PRIVATE ${SHIM_DIR} ${GEN_DIR} ${T_INCLUDES})
   target_compile_definitions(${NAME} PRIVATE ${T_DEFINES})
   target_compile_options(${NAME} PRIVATE ${TEST_C_FLAGS})
   target_link_libraries(${NAME} PRIVATE unity zephyr_sim)
   add_dependencies(${NAME} wire_vectors)
   add_test(NAME ${NAME}
      COMMAND Python3::Interpreter ${TOOLS_DIR}/run_unity.py
         ${REPORT_DIR}/junit/${NAME}.xml ${NAME} $<TARGET_FILE:${NAME}> ${T_ARGS})
endfunction()

set(SETU_DIR ${REPO_ROOT}/_LIB/SETU)
set(GATT_CB_DIR ${REPO_ROOT}/_LIB/GATT_CB)
set(ASW_DIR ${REPO_ROOT}/_ASW)
set(SETU_INCLUDES ${SETU_DIR} ${ASW_DIR}/_BLE_GENERIX ${CMAKE_CURRENT_SOURCE_DIR}/unit/SETU)

# ---- _LIB/SETU -----------------------------------------------------------
add_unit_test(setu_frame
   SOURCES unit/SETU/test_frame.c ${SETU_DIR}/SETU_Frame.c
   INCLUDES ${SETU_INCLUDES})

# The engine test #includes Core/Server/Client .c; built once per role set
foreach(ROLE both server client)
   set(ROLE_DEFS "")
   if(ROLE STREQUAL "server")
      set(ROLE_DEFS SETU_ENABLE_CLIENT=0)
   elseif(ROLE STREQUAL "client")
      set(ROLE_DEFS SETU_ENABLE_SERVER=0)
   endif()
   add_unit_test(setu_engine_${ROLE}
      SOURCES unit/SETU/test_engine.c ${SETU_DIR}/SETU_Frame.c
      INCLUDES ${SETU_INCLUDES}
      DEFINES CONFIG_BT_GATT_CLIENT SETU_RX_POOL_DEPTH=6 ${ROLE_DEFS})
endforeach()

# ---- _LIB/GATT_CB ------------------------------------------------------------
add_unit_test(gatt_cb
   SOURCES unit/GATT_CB/test_gatt_cb.c ${GATT_CB_DIR}/GATT_GenericCallbacks.c
   INCLUDES ${GATT_CB_DIR})

# ---- _LIB/FileSysManager -----------------------------------------------------
# Manager + FSM (#included) on the in-memory volume of shim/fs_sim.c; built
# with the write buffer (as CONFIG_FSMGR_BUFFERED_WRITE) and without
set(FSMGR_DIR ${REPO_ROOT}/_LIB/FileSysManager)
add_unit_test(fsmgr
   SOURCES unit/FileSysManager/test_fsmgr.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${FSMGR_DIR}
   DEFINES FSMGR_WRITE_BUFFER_SIZE=512)
add_unit_test(fsmgr_direct
   SOURCES unit/FileSysManager/test_fsmgr.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${FSMGR_DIR}
   DEFINES FSMGR_WRITE_BUFFER_SIZE=0)

# ---- _ASW/_DATA_STORE --------------------------------------------------------
# test_datastore.c #includes DataStore.c with the SETU Server stubbed out;
# built with the summary line (default) and with the full hex dump.
# BEGIN / COMMIT run on the real File System Manager (#included) over fs_sim.c.
set(DS_INCLUDES ${ASW_DIR}/_DATA_STORE ${ASW_DIR}/_SETU_SVC ${FSMGR_DIR} ${SETU_INCLUDES})
add_unit_test(datastore
   SOURCES unit/DataStore/test_datastore.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${DS_INCLUDES})
add_unit_test(datastore_hexdump
   SOURCES unit/DataStore/test_datastore.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${DS_INCLUDES}
   DEFINES CONFIG_DS_HEX_DUMP=1)

# Hex upload end to end: real SETU Server + DataStore + File System
# Manager, simulated link and peer client, fed with the first segment of
# AA00000100.hex
add_unit_test(hex_upload_e2e
   SOURCES unit/DataStore/test_upload_e2e.c ${SETU_DIR}/SETU_Frame.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${DS_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT SETU_ENABLE_CLIENT=0)

# ---- _ASW/_FS_CMD ------------------------------------------------------------
# File commands over BLE: router + File System Manager (#included) on fs_sim.c,
# SETU Server and data store stubbed; with CONFIG_FS_CMD and without
set(FSCMD_INCLUDES ${ASW_DIR}/_FS_CMD ${DS_INCLUDES})
add_unit_test(fscmd
   SOURCES unit/FsCmd/test_fscmd.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${FSCMD_INCLUDES}
   DEFINES CONFIG_FS_CMD=1)
add_unit_test(fscmd_disabled
   SOURCES unit/FsCmd/test_fscmd.c ${SHIM_DIR}/fs_sim.c
   INCLUDES ${FSCMD_INCLUDES})

# ---- _ASW/_CAN -------------------------------------------------------------------
# CAN / CAN FD interface against a scripted controller (Zephyr's CAN API): a CAN
# FD build with the self-test and traffic log, and a CAN 2.0 build with neither
set(CANIF_INCLUDES ${ASW_DIR}/_CAN)
add_unit_test(canif
   SOURCES unit/CanIf/test_canif.c
   INCLUDES ${CANIF_INCLUDES}
   DEFINES CONFIG_CAN_FD_MODE=1 CONFIG_CANIF_FD=1 CONFIG_CANIF_SELFTEST=1 CONFIG_CANIF_LOG_RX=1)
add_unit_test(canif_classic
   SOURCES unit/CanIf/test_canif.c
   INCLUDES ${CANIF_INCLUDES})

# ---- _ASW/_SETU_SVC -----------------------------------------------------------
# The appType router, with the GATT service and both SETU roles stubbed
add_unit_test(setu_router
   SOURCES unit/SETUSvc/test_router.c
   INCLUDES ${ASW_DIR}/_SETU_SVC ${SETU_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# ---- _ASW/_PROV --------------------------------------------------------------
# Provisioning flow; key/CSR, certificate verification, PSA, router and the
# SETU roles are stubbed (each has its own test)
set(PROV_INCLUDES ${ASW_DIR}/_PROV ${ASW_DIR}/_PAIR ${ASW_DIR}/_SETU_SVC ${ASW_DIR}/_CSR ${ASW_DIR}/_DEVICE_CERT
   ${PSA_STUB_DIR} ${SETU_INCLUDES})
add_unit_test(prov
   SOURCES unit/Prov/test_prov.c
   INCLUDES ${PROV_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# Provisioning end to end: real SETU (both roles) + router + Prov.c over the
# simulated link, with the peer as the provisioner
add_unit_test(prov_e2e
   SOURCES unit/Prov/test_prov_e2e.c ${SETU_DIR}/SETU_Frame.c
   INCLUDES ${PROV_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# The wipe button: DK library and gv_Prov_RequestWipe stubbed, simulated time
add_unit_test(prov_button
   SOURCES unit/Prov/test_prov_button.c
   INCLUDES ${PROV_INCLUDES})

# ---- _ASW/_PAIR --------------------------------------------------------------
# Pairing flow (Pair.c): BT stack, SETU, router, certificate verification,
# OOB signing, provisioning, LEDs and the service stubbed (calls recorded)
set(PAIR_INCLUDES ${ASW_DIR}/_PAIR ${ASW_DIR}/_PROV ${ASW_DIR}/_SETU_SVC ${ASW_DIR}/_CSR
   ${ASW_DIR}/_DEVICE_CERT ${PSA_STUB_DIR} ${SETU_INCLUDES})
add_unit_test(pair
   SOURCES unit/Pair/test_pair.c
   INCLUDES ${PAIR_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# Pairing end to end: real SETU (both roles) + router + Pair.c over the
# simulated link, with the peer as the other device and a second link as host
add_unit_test(pair_e2e
   SOURCES unit/Pair/test_pair_e2e.c ${SETU_DIR}/SETU_Frame.c
   INCLUDES ${PAIR_INCLUDES}
   DEFINES CONFIG_BT_GATT_CLIENT)

# Signed OOB data (PairOob.c) with the real TF-PSA-Crypto, against the vector
# signed by Python's cryptography
add_unit_test(pair_oob
   SOURCES unit/Pair/test_pair_oob.c ${TFPSA_SHIM_DIR}/tfpsa_host_platform.c
   INCLUDES ${ASW_DIR}/_PAIR)
target_link_libraries(pair_oob PRIVATE tfpsacrypto)

# ---- _ASW/_DEVICE_CERT -------------------------------------------------------
# Certificate storage (DeviceCert.c) against an in-memory PSA ITS
add_unit_test(devicecert_store
   SOURCES unit/DeviceCert/test_devicecert_store.c
   INCLUDES ${ASW_DIR}/_DEVICE_CERT ${ASW_DIR}/_CSR ${PSA_STUB_DIR})

# X.509 verification (DeviceCert_Verify.c) with the real Mbed TLS / TF-PSA-Crypto.
# The certificates come from the PC tool's CA and negative set
# (tools/gen_cert_vectors.py, new keys on each fresh build; needs cryptography).
set(PKI_DIR ${REPO_ROOT}/_TOOLS/BleHostGUI/blehost/pki)
add_custom_command(
   OUTPUT ${GEN_DIR}/cert_vectors.h
   COMMAND Python3::Interpreter ${TOOLS_DIR}/gen_cert_vectors.py ${GEN_DIR}/cert_vectors.h
   DEPENDS ${TOOLS_DIR}/gen_cert_vectors.py ${PKI_DIR}/authority.py ${PKI_DIR}/negative.py
   COMMENT "Generating cert_vectors.h")
add_custom_target(cert_vectors DEPENDS ${GEN_DIR}/cert_vectors.h)
add_unit_test(devicecert_verify
   SOURCES unit/DeviceCert/test_devicecert_verify.c ${TFPSA_SHIM_DIR}/tfpsa_host_platform.c
   INCLUDES ${ASW_DIR}/_DEVICE_CERT ${ASW_DIR}/_CSR)
add_dependencies(devicecert_verify cert_vectors)
target_link_libraries(devicecert_verify PRIVATE mbedx509)
# The platform file implements TF-PSA-Crypto's own ITS interface (core/)
set_source_files_properties(${TFPSA_SHIM_DIR}/tfpsa_host_platform.c PROPERTIES
   INCLUDE_DIRECTORIES ${mbedtls_SOURCE_DIR}/tf-psa-crypto/core)

# ---- _ASW/_CSR ---------------------------------------------------------------
# The sample's CSR DER encoder, with PSA stubbed by the "csr" vector of wire.json
# (gen_csr_vector.py rebuilds this target to regenerate that vector)
add_unit_test(csr_der
   SOURCES unit/CSR/test_der.c
   INCLUDES ${ASW_DIR}/_CSR ${PSA_STUB_DIR})

# Key and CSR life cycle (CSR_Generator.c): PSA, ITS, HUK, settings, hardware
# ID and the DER encoder stubbed. Its init result is kept for the life of the
# process, so each init failure runs as its own CTest entry.
add_unit_test(csr_generator
   SOURCES unit/CSR/test_csr_generator.c
   INCLUDES ${ASW_DIR}/_CSR ${PSA_STUB_DIR})
foreach(MODE huk-present huk-fail settings-fail crypto-fail)
   add_test(NAME csr_generator_init_${MODE}
      COMMAND Python3::Interpreter ${TOOLS_DIR}/run_unity.py
         ${REPORT_DIR}/junit/csr_generator_init_${MODE}.xml csr_generator_init_${MODE}
         $<TARGET_FILE:csr_generator> --init=${MODE})
endforeach()

# ---- _ASW/_GENERIX -----------------------------------------------------------
add_unit_test(helpers
   SOURCES unit/Helpers/test_helpers.c ${ASW_DIR}/_GENERIX/Helpers.c
   INCLUDES ${ASW_DIR}/_GENERIX)

# ---- Header hygiene: each header of a tested unit compiles on its own -------
set(CHECKED_HEADERS
   ${SETU_DIR}/SETU.h ${SETU_DIR}/SETU_Client.h ${SETU_DIR}/SETU_Config.h
   ${SETU_DIR}/SETU_Frame.h ${SETU_DIR}/SETU_Server.h ${SETU_DIR}/SETU_Types.h
   ${SETU_DIR}/SETU_Uuid.h
   ${FSMGR_DIR}/FileSysManager.h ${FSMGR_DIR}/FileSysManagerFSM.h
   ${FSMGR_DIR}/FileSysManager_Types.h ${FSMGR_DIR}/FileSysManager_Config.h
   ${ASW_DIR}/_FS_CMD/FsCmd.h
   ${ASW_DIR}/_CAN/CanIf.h
   ${GATT_CB_DIR}/GATT_CB_Types.h ${GATT_CB_DIR}/GATT_GenericCallbacks.h
   ${ASW_DIR}/_SETU_SVC/SETUSvc.h ${ASW_DIR}/_SETU_SVC/SETURouter.h ${ASW_DIR}/_DATA_STORE/DataStore.h
   ${ASW_DIR}/_PROV/Prov.h ${ASW_DIR}/_PROV/ProvButton.h
   ${ASW_DIR}/_PAIR/Pair.h ${ASW_DIR}/_PAIR/PairOob.h ${ASW_DIR}/_PAIR/PairSvc.h
   ${ASW_DIR}/_DEVICE_CERT/DeviceCert.h ${ASW_DIR}/_DEVICE_CERT/DeviceCert_Verify.h
   ${ASW_DIR}/_DEVICE_CERT/DeviceCert_Types.h ${ASW_DIR}/_DEVICE_CERT/DeviceCert_Config.h
   ${ASW_DIR}/_CSR/CSR_Generator.h ${ASW_DIR}/_CSR/CSR_Generator_Types.h
   ${ASW_DIR}/_CSR/CSR_Generator_Config.h ${ASW_DIR}/_CSR/DER.h
   ${ASW_DIR}/_GENERIX/Helpers.h)
set(HDR_INCLUDES "")
foreach(DIR ${SHIM_DIR} ${SETU_INCLUDES} ${GATT_CB_DIR} ${FSCMD_INCLUDES} ${PROV_INCLUDES} ${ASW_DIR}/_GENERIX)
   list(APPEND HDR_INCLUDES -I${DIR})
endforeach()
add_test(NAME header_hygiene
   COMMAND Python3::Interpreter ${TOOLS_DIR}/check_headers.py
      ${REPORT_DIR}/junit/header_hygiene.xml ${CMAKE_CURRENT_SOURCE_DIR}/known_header_issues.txt
      ${CMAKE_C_COMPILER} ${TEST_C_FLAGS} ${HDR_INCLUDES} -- ${CHECKED_HEADERS})
