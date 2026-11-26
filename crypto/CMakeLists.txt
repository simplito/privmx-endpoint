# The whole backend is pmx-crypto (pmxcrypto/): primitives, compositions and EC key operations.
# The `privmx::crypto` API above it is unchanged, so rpc/, privfs/ and the parts of endpoint/ still
# on the legacy stack compile untouched - what went are both crypto plugins, and with them the
# pinned OpenSSL version they forced on the dependency graph. The "OPENSSL" and "EMSCRIPTEN"
# backends had already stopped reaching any artifact around 2.6, because the choice always resolved
# to DRIVER.
#
# There is no backend switch any more: one backend means the base factories (CryptoEnv::getEnv,
# ECCImpl::fromPrivateKey and friends) are defined here unconditionally, where they used to sit
# behind PRIVMX_DEFAULT_CRYPTO_DRIVER. That option named a driver that no longer exists and could
# never be OFF, so it is gone rather than renamed - and with it the generated CryptoConfig.hpp,
# whose only content it was.
#
# Vectors pin the formats: CompositionVectorsTest (PRF, encrypt-then-MAC), FormatHashVectorsTest
# (the KDF) and EccVectorsTest (key encodings, the signature frame, ECDH, the curve order). Each set
# passed against the driver implementation first and against this one after, which is how the bytes
# on the wire are known not to have moved.

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)
file(GLOB_RECURSE SOURCES_PMXCRYPTO ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/src/*.cpp)
list(APPEND SOURCES ${SOURCES_PMXCRYPTO})

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/include
)
set(LIBS privmxcryptolib)

if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/include/privmx DESTINATION include)
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
