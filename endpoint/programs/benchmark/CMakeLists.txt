file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)


add_executable(privmxBenchmark ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp ${SOURCES})
target_include_directories(privmxBenchmark PUBLIC ${INCLUDE_DIRS})
target_link_libraries(privmxBenchmark privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util)

add_executable(privmxPerformanceTester ${CMAKE_CURRENT_SOURCE_DIR}/PerformanceTester.cpp ${SOURCES})
target_include_directories(privmxPerformanceTester PUBLIC ${INCLUDE_DIRS})
target_link_libraries(privmxPerformanceTester privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util)