# SETU: this device runs both roles. The Server receives hex segments and
# certificates; the Client sends the CSR to the provisioner (the PC hosts a
# SETU service for it). Server notifications + Client writes in flight must
# stay below the RX-priority CONFIG_BT_ATT_TX_COUNT (6) in prj.conf, so the
# Client is limited to 3 writes in flight (2 + 3 < 6). The CSR is under 1 KiB,
# so the lower window costs nothing.
zephyr_compile_definitions(SETU_ENABLE_SERVER=1 SETU_ENABLE_CLIENT=1
   SETU_CLI_WRITE_INFLIGHT_MAX=3U)

# GATT_CB first: the SETU Server sits on top of the generic GATT callbacks
add_subdirectory(GATT_CB)
add_subdirectory(SETU)
# The FAT file system on the external flash (hex uploads are stored there)
add_subdirectory(FileSysManager)
# The UDS client (ISO 14229, tester side) on Zephyr's ISO-TP
add_subdirectory(UdsClient)
