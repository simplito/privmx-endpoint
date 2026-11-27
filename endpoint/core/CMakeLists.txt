file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(INCLUDE_PUB_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include_pub)

if(BUILD_SHARED_LIBS)
    add_library(privmxendpointcore SHARED ${SOURCES})
else()
    add_library(privmxendpointcore STATIC ${SOURCES})
endif()
target_include_directories(privmxendpointcore PUBLIC ${INCLUDE_DIRS} PUBLIC ${INCLUDE_PUB_DIRS})
target_compile_options(privmxendpointcore PRIVATE -fPIC -Wall -Wextra)
# MINIMAL_BUILD used to be set here by `set_target_properties(... COMPILE_DEFINITIONS ...)`, which
# **overwrites** the whole property — every definition added earlier by `target_compile_definitions`
# silently vanished. `target_compile_definitions` appends, so ordering no longer matters.
#
# PRIVMX_DEFAULT_CRYPTO_SUITE_ID: the write-suite choice (level 1). See the top-level CMakeLists.
target_compile_definitions(privmxendpointcore
    PRIVATE MINIMAL_BUILD
    PRIVATE PRIVMX_DEFAULT_CRYPTO_SUITE_ID=${PRIVMX_DEFAULT_CRYPTO_SUITE_ID}
    PRIVATE PRIVMX_DEFAULT_KEY_ALGORITHM_TAG=${PRIVMX_DEFAULT_KEY_ALGORITHM_TAG})
# privmxcryptolib is PUBLIC because core's public headers (crypto/PrivateKey.hpp and relatives)
# expose pmx-crypto types — consumers need its include paths.
target_link_libraries(privmxendpointcore PRIVATE Poco::Foundation privmx PUBLIC privmxcryptolib)
if(BUILD_SHARED_LIBS)
    set_target_properties(privmxendpointcore PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()
install(TARGETS privmxendpointcore DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include_pub/privmx DESTINATION include)
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/privmx DESTINATION include)
endif()
if(PRIVMX_WERROR)
    target_compile_options(privmxendpointcore PRIVATE -Werror)
endif()

if(PRIVMX_ENABLE_TESTS)
    include(FindGTest)
    include(GoogleTest)
    enable_testing()
    find_package(GTest REQUIRED)
    file(GLOB_RECURSE CORE_TESTS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp)
    add_executable(privmxendpointcore_test ${CORE_TESTS_SOURCES})
    target_link_libraries(privmxendpointcore_test
        PUBLIC Poco::Foundation Poco::JSON privmx privmxendpointcore privmxcryptolib GTest::gtest_main)
    gtest_add_tests(TARGET privmxendpointcore_test)
endif()
