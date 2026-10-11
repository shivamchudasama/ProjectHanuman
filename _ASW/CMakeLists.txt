file(GLOB APP_SOURCES CONFIGURE_DEPENDS
   "*.c"
)

target_sources(app PRIVATE
   ${APP_SOURCES}
)

target_include_directories(app PRIVATE
   ${CMAKE_CURRENT_LIST_DIR}
)

add_subdirectory(_BLE)
add_subdirectory(_BLE_GENERIX)
add_subdirectory(_GENERIX)
add_subdirectory(_GAP)
add_subdirectory(_APP_LOG)
add_subdirectory(_SETU_SVC)
add_subdirectory(_DATA_STORE)
add_subdirectory(_FS_CMD)
add_subdirectory(_CSR)
add_subdirectory(_DEVICE_CERT)
add_subdirectory(_PROV)
add_subdirectory(_PAIR)
add_subdirectory(_CAN)
