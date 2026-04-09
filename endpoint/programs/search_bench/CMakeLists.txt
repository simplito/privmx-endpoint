target_include_directories(privmxendpointcrypto PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointevent PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointkvdb PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointsearch PRIVATE ${INCLUDE_DIRS})

# search_bench
add_executable(search_bench ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_link_libraries(search_bench privmx privmxendpointcore privmxendpointcrypto privmxendpointstore privmxendpointkvdb privmxendpointsearch)
