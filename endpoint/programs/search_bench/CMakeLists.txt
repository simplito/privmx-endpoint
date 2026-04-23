target_include_directories(privmxendpointcrypto PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointevent PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointkvdb PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointsearch PRIVATE ${INCLUDE_DIRS})

# search_bench
file(GLOB_RECURSE SEARCH_BENCH_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_executable(search_bench ${SEARCH_BENCH_SOURCES})
target_include_directories(search_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(search_bench privmx privmxendpointcore privmxendpointcrypto privmxendpointstore privmxendpointkvdb privmxendpointsearch)
