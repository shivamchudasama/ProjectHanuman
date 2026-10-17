file(GLOB APP_SOURCES CONFIGURE_DEPENDS
   "*.c"
)

# Built only with the application watchdog (CONFIG_APP_WDT, which needs CONFIG_TASK_WDT)
if(CONFIG_APP_WDT)
   target_sources(app PRIVATE
      ${APP_SOURCES}
   )
endif()

target_include_directories(app PRIVATE
   ${CMAKE_CURRENT_LIST_DIR}
)
