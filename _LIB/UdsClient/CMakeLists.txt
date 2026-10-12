file(GLOB APP_SOURCES CONFIGURE_DEPENDS
   "*.c"
)

# Built only with the UDS feature (CONFIG_UDS, which needs CONFIG_ISOTP)
if(CONFIG_UDS)
   target_sources(app PRIVATE
      ${APP_SOURCES}
   )
endif()

target_include_directories(app PRIVATE
   ${CMAKE_CURRENT_LIST_DIR}
)
