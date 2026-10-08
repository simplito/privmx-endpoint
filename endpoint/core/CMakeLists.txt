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
# MINIMAL_BUILD bylo tu ustawiane przez `set_target_properties(... COMPILE_DEFINITIONS ...)`, ktore
# **nadpisuje** cala wlasciwosc - kazda definicja dodana wczesniej przez `target_compile_definitions`
# cicho znikala. `target_compile_definitions` dokleja, wiec kolejnosc przestaje mie znaczenie.
#
# PRIVMX_DEFAULT_CRYPTO_SUITE_ID: wybor zestawu zapisu (poziom 1). Patrz glowny CMakeLists.
target_compile_definitions(privmxendpointcore
    PRIVATE MINIMAL_BUILD
    PRIVATE PRIVMX_DEFAULT_CRYPTO_SUITE_ID=${PRIVMX_DEFAULT_CRYPTO_SUITE_ID})
# privmxcryptolib jest PUBLIC, bo publiczne naglowki core (crypto/PrivateKey.hpp i spokrewnione)
# wystawiaja typy z pmx-crypto - konsumenci potrzebuja jego sciezek include.
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
