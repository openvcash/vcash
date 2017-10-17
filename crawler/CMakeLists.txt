# Builds the crawler library
# Add/delete paths to .cpp files when more are created/deleted.

add_library(crawler STATIC
  src/database_stack.cpp
  src/http_transport.cpp
  src/probe_manager.cpp
  src/stack_impl.cpp
  src/stack.cpp
)

target_link_libraries(crawler
  PUBLIC database
)

target_include_directories(crawler
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

IF(INSTALL_LIBCRAWLER)
  install_and_export("crawler")
ENDIF()
