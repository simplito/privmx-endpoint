# Backendy "OPENSSL" i "EMSCRIPTEN" zostaly usuniete: wybor backendu i tak zawsze
# rozstrzygal sie na DRIVER, wiec ich zrodla nie trafialy do zadnego artefaktu
# od ok. wersji 2.6.
#
# Prymitywy (hasze, HMAC, AES, PBKDF2, losowosc) realizuje teraz pmx-crypto - patrz
# pmxcrypto/. API `privmx::crypto` sie nie zmienia, wiec rpc/, privfs/ i czesci endpointu
# nadal siedzace na starym stosie kompiluja sie bez zmian, a privmxdrvcrypto znika.
#
# Z driver/ zostaje wylacznie ecc/ (privmxdrvecc): BNImpl i PointImpl to arytmetyka
# duzych liczb i punktow krzywej, ktorej pmx-crypto nie wystawia - ma klucze, nie goly
# BN. ECCImpl to z kolei podpisy i wyprowadzanie kluczy starych typow `crypto::ecc::*`.
# Dlatego granica tej zmiany biegnie tutaj.
set(PRIVMX_DEFAULT_CRYPTO_DRIVER ON)

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)
file(GLOB_RECURSE SOURCES_PMXCRYPTO ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/src/*.cpp)
# Celowo nie GLOB_RECURSE po calym driver/src: CryptoService.cpp i CryptoEnv.cpp zastapil
# backend pmxcrypto, a `CryptoEnv::getEnv()` moze byc zdefiniowane tylko w jednej jednostce.
file(GLOB_RECURSE SOURCES_DRIVER_ECC ${CMAKE_CURRENT_SOURCE_DIR}/driver/src/ecc/*.cpp)
list(APPEND SOURCES ${SOURCES_PMXCRYPTO} ${SOURCES_DRIVER_ECC})

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/driver/include
    ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
)
set(LIBS privmxcryptolib privmxdrvecc)

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
