# Kryptografia jest realizowana wylacznie przez drivery (privmxdrvcrypto / privmxdrvecc).
# Backendy "OPENSSL" i "EMSCRIPTEN" zostaly usuniete: wybor backendu i tak zawsze
# rozstrzygal sie na DRIVER, wiec ich zrodla nie trafialy do zadnego artefaktu
# od ok. wersji 2.6.
set(PRIVMX_DEFAULT_CRYPTO_DRIVER ON)

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)
file(GLOB_RECURSE SOURCES_DRIVER ${CMAKE_CURRENT_SOURCE_DIR}/driver/src/*.cpp)
list(APPEND SOURCES ${SOURCES_DRIVER})

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/driver/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
)
set(LIBS privmxdrvcrypto privmxdrvecc)

if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/driver/include/privmx DESTINATION include)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/base/include/privmx/crypto/CryptoConfig.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/crypto/CryptoConfig.hpp @ONLY)
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/crypto/CryptoConfig.hpp DESTINATION include/privmx/crypto)
endif()

add_library(privmxcrypto OBJECT ${SOURCES})
target_include_directories(privmxcrypto PUBLIC ${INCLUDE_DIRS})
target_compile_options(privmxcrypto PRIVATE -Wall -Wextra -fPIC -Wno-narrowing)
target_link_libraries(privmxcrypto PUBLIC Poco::Foundation privmxutils gmp ${LIBS})
if(BUILD_SHARED_LIBS)
    set_target_properties(privmxcrypto PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/base/include/privmx DESTINATION include)
endif()
if(PRIVMX_WERROR)
    target_compile_options(privmxcrypto PRIVATE -Werror)
endif()
if(PRIVMX_ENABLE_TESTS)
    include(FindGTest)
    include(GoogleTest)
    enable_testing()
    find_package(GTest REQUIRED)
    file(GLOB_RECURSE TESTS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/test/*.cpp)
    add_executable(privmxcrypto_test ${TESTS_SOURCES})
    target_link_libraries(privmxcrypto_test PUBLIC Poco::Foundation Poco::JSON Pson privmxutils privmxcrypto GTest::GTest GTest::Main)
    gtest_add_tests(TARGET privmxcrypto_test)
endif()
