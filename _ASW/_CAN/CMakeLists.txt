file(GLOB APP_SOURCES CONFIGURE_DEPENDS
   "*.c"
)

# Built only with the CAN interface (CONFIG_CANIF, which needs CONFIG_CAN)
if(CONFIG_CANIF)
   target_sources(app PRIVATE
      ${APP_SOURCES}
   )
endif()

target_include_directories(app PRIVATE
   ${CMAKE_CURRENT_LIST_DIR}
)
