set(PRIVMX_CRYPTO "OPENSSL" CACHE STRING "Crypto module")
option(PRIVMX_ENABLE_CRYPTO_OPENSSL "Enable Crypto OpenSSL" OFF)
option(PRIVMX_ENABLE_CRYPTO_EMSCRIPTEN "Enable Crypto Emscripten" OFF)
option(PRIVMX_ENABLE_CRYPTO_DRIVER "Enable Crypto Driver" OFF)

if(PRIVMX_EMSCRIPTEN)
    set(PRIVMX_CRYPTO "EMSCRIPTEN")
endif()

if(PRIVMX_DRIVER_CRYPTO)
    set(PRIVMX_CRYPTO "DRIVER")
endif()

message(STATUS "PRIVMX_CRYPTO=${PRIVMX_CRYPTO}")

if(PRIVMX_CRYPTO STREQUAL "OPENSSL")
    set(PRIVMX_ENABLE_CRYPTO_OPENSSL ON)
    set(PRIVMX_DEFAULT_CRYPTO_OPENSSL ON)
elseif(PRIVMX_CRYPTO STREQUAL "EMSCRIPTEN")
    set(PRIVMX_ENABLE_CRYPTO_EMSCRIPTEN ON)
    set(PRIVMX_DEFAULT_CRYPTO_EMSCRIPTEN ON)
elseif(PRIVMX_CRYPTO STREQUAL "DRIVER")
    set(PRIVMX_ENABLE_CRYPTO_DRIVER ON)
    set(PRIVMX_DEFAULT_CRYPTO_DRIVER ON)
endif()

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/base/include ${CMAKE_CURRENT_BINARY_DIR}/include)
set(LIBS "")

if(PRIVMX_ENABLE_CRYPTO_OPENSSL)
    file(GLOB_RECURSE SOURCES_OPENSSL ${CMAKE_CURRENT_SOURCE_DIR}/openssl/src/*.cpp)
    list(APPEND SOURCES ${SOURCES_OPENSSL})
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include)
    list(APPEND LIBS Poco::Crypto OpenSSL::Crypto)
    if(PRIVMX_INSTALL_PRIVATE_HEADERS)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include/privmx DESTINATION include)
    endif()
endif(PRIVMX_ENABLE_CRYPTO_OPENSSL)

if(PRIVMX_ENABLE_CRYPTO_EMSCRIPTEN)
    file(GLOB_RECURSE SOURCES_EMSCRIPTEN ${CMAKE_CURRENT_SOURCE_DIR}/emscripten/src/*.cpp)
    list(APPEND SOURCES ${SOURCES_EMSCRIPTEN})
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/emscripten/include)
    if(PRIVMX_INSTALL_PRIVATE_HEADERS)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/emscripten/include/privmx DESTINATION include)
    endif()
endif(PRIVMX_ENABLE_CRYPTO_EMSCRIPTEN)

if(PRIVMX_ENABLE_CRYPTO_DRIVER)
    file(GLOB_RECURSE SOURCES_DRIVER ${CMAKE_CURRENT_SOURCE_DIR}/driver/src/*.cpp)
    list(APPEND SOURCES ${SOURCES_DRIVER})
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/driver/include)
    if(PRIVMX_INSTALL_PRIVATE_HEADERS)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/driver/include/privmx DESTINATION include)
    endif()
    list(APPEND LIBS privmxdrvcrypto privmxdrvecc)
endif(PRIVMX_ENABLE_CRYPTO_DRIVER)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/base/include/privmx/crypto/CryptoConfig.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/crypto/CryptoConfig.hpp @ONLY)
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/crypto/CryptoConfig.hpp DESTINATION include/privmx/crypto)
endif()

add_library(privmxcrypto OBJECT ${SOURCES})
target_include_directories(privmxcrypto PUBLIC ${INCLUDE_DIRS})
target_compile_options(privmxcrypto PRIVATE -fPIC -Wall -Wextra -Wno-narrowing)
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
if(PRIVMX_ENABLE_CRYPTO_OPENSSL)
    target_compile_definitions(privmxcrypto PRIVATE -DOPENSSL_SUPPRESS_DEPRECATED)
endif(PRIVMX_ENABLE_CRYPTO_OPENSSL)

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
