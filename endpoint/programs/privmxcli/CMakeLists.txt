file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)


add_executable(privmxcli ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp ${SOURCES})
target_include_directories(privmxcli PUBLIC ${INCLUDE_DIRS})
target_link_libraries(privmxcli PRIVATE privmxendpoint Poco::Foundation Threads::Threads readline)

if(PRIVMX_ENABLE_TESTS)
    include(FindGTest)
    include(GoogleTest)
    enable_testing()
    find_package(GTest REQUIRED)
    file(GLOB_RECURSE TESTS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp ${SOURCES})
    add_executable(privmxcli_tests ${TESTS_SOURCES})
    target_include_directories(privmxcli_tests PUBLIC ${INCLUDE_DIRS})
    target_link_libraries(privmxcli_tests PUBLIC Poco::Foundation Threads::Threads readline privmxendpoint GTest::GTest GTest::Main)
    gtest_add_tests(TARGET privmxcli_tests)
endif()