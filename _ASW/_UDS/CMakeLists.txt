file(GLOB APP_SOURCES CONFIGURE_DEPENDS
   "*.c"
)

# Built only with the UDS feature (CONFIG_UDS)
if(CONFIG_UDS)
   target_sources(app PRIVATE
      ${APP_SOURCES}
   )

   # OEM seed -> key algorithms (0x80-0xFF) live in a private, git-ignored
   # oem/ folder; when it exists its sources implement gi_UdsKey_Oem()
   file(GLOB OEM_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/oem/*.c")
   if(OEM_SOURCES)
      target_sources(app PRIVATE ${OEM_SOURCES})
      target_compile_definitions(app PRIVATE UDS_KEY_OEM=1)
   endif()
endif()

target_include_directories(app PRIVATE
   ${CMAKE_CURRENT_LIST_DIR}
)
