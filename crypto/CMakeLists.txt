# Backendy "OPENSSL" i "EMSCRIPTEN" zostaly usuniete: wybor backendu i tak zawsze
# rozstrzygal sie na DRIVER, wiec ich zrodla nie trafialy do zadnego artefaktu
# od ok. wersji 2.6.
#
# Caly backend to teraz pmx-crypto (pmxcrypto/): prymitywy, kompozycje i operacje na
# kluczach EC. API `privmx::crypto` sie nie zmienia, wiec rpc/, privfs/ i czesci endpointu
# nadal siedzace na starym stosie kompiluja sie bez zmian - znikaja za to obie wtyczki
# kryptograficzne, a z nimi wymuszanie jednej wersji OpenSSL-a w grafie zaleznosci.
#
# Formaty pilnuja wektory: CompositionVectorsTest (kdf, PRF, encrypt-then-MAC) oraz
# EccVectorsTest (kodowanie kluczy, ramka podpisu, ECDH, rzad krzywej). Oba zestawy
# przeszly najpierw na implementacji driverowej, a potem na tej - stad wiadomo, ze
# bajty na drucie sie nie zmienily.
set(PRIVMX_DEFAULT_CRYPTO_DRIVER ON)

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)
file(GLOB_RECURSE SOURCES_PMXCRYPTO ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/src/*.cpp)
list(APPEND SOURCES ${SOURCES_PMXCRYPTO})

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
)
set(LIBS privmxcryptolib)

if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pmxcrypto/include/privmx DESTINATION include)
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
