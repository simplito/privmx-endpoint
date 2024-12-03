file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)


add_executable(privmxBenchmark ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp ${SOURCES})
target_include_directories(privmxBenchmark PUBLIC ${INCLUDE_DIRS})
target_link_libraries(privmxBenchmark privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util)
