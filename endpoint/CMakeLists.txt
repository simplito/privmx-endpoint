
option(PRIVMX_BUILD_ENDPOINT_PING "Build endpoint ping" OFF)
message(STATUS "Build endpoint ping - PRIVMX_BUILD_ENDPOINT_PING=${PRIVMX_BUILD_ENDPOINT_PING}")

option(ENDPOINT_MINIMAL_BUILD "edpoint minimal build" OFF)

if(ENDPOINT_MINIMAL_BUILD)
  add_definitions(-DMINIMAL_BUILD)
endif()

option(PRIVMX_BUILD_ENDPOINT_ENDPOINT "Build endpoint endpoint" ON)
option(PRIVMX_BUILD_ENDPOINT_INTERFACE "Build endpoint interface" OFF)
option(PRIVMX_BUILD_ANDROID_HELPER "Build android helper" OFF)
message(STATUS "Build endpoint ping - PRIVMX_BUILD_ENDPOINT_ENDPOINT=${PRIVMX_BUILD_ENDPOINT_ENDPOINT}")
if(PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(core)
    add_subdirectory(crypto)
    add_subdirectory(event)
    add_subdirectory(thread)
    add_subdirectory(store)
    add_subdirectory(kvdb)
    add_subdirectory(inbox)
    add_subdirectory(stream)
    if (PRIVMX_BUILD_ANDROID_HELPER)
        add_subdirectory(android)
    endif(PRIVMX_BUILD_ANDROID_HELPER)
endif(PRIVMX_BUILD_ENDPOINT_ENDPOINT)

if(PRIVMX_BUILD_CLI AND PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(programs/privmxcli)
endif()

if(PRIVMX_BUILD_BENCHMARK AND PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(programs/benchmark)
endif()

if(PRIVMX_BUILD_STREAM_TESTING AND PRIVMX_BUILD_ENDPOINT_ENDPOINT)
    add_subdirectory(programs/stream_testing)
endif()