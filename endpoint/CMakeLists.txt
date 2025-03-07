
option(PRIVMX_BUILD_ENDPOINT_PING "Build endpoint ping" OFF)
message(STATUS "Build endpoint ping - PRIVMX_BUILD_ENDPOINT_PING=${PRIVMX_BUILD_ENDPOINT_PING}")

option(ENDPOINT_MINIMAL_BUILD "edpoint minimal build" OFF)

if(ENDPOINT_MINIMAL_BUILD)
  add_definitions(-DMINIMAL_BUILD)
endif()

option(PRIVMX_BUILD_ENDPOINT_ENDPOINT "Build endpoint endpoint" ON)
message(STATUS "Build endpoint ping - PRIVMX_BUILD_ENDPOINT_ENDPOINT=${PRIVMX_BUILD_ENDPOINT_ENDPOINT}")
if(PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(core)
    add_subdirectory(crypto)
    add_subdirectory(thread)
    add_subdirectory(store)
    add_subdirectory(inbox)
    add_subdirectory(event)
endif(PRIVMX_BUILD_ENDPOINT_ENDPOINT)

if(PRIVMX_ENABLE_TESTS_E2E)
    add_subdirectory(tests_e2e)
endif()

option(PRIVMX_BUILD_ENDPOINT_INTERFACE "Build endpoint interface" OFF)
if(PRIVMX_BUILD_ENDPOINT_INTERFACE)
    add_subdirectory(interface)
endif(PRIVMX_BUILD_ENDPOINT_INTERFACE)

if(PRIVMX_BUILD_CLI AND PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(programs/privmxcli)
endif()

if(PRIVMX_BUILD_BENCHMARK AND PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(programs/benchmark)
endif()
