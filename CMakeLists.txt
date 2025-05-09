cmake_minimum_required(VERSION 3.10.2)
add_definitions(
    -Wfatal-errors
    )
project(privmxlib)

include(FindOpenSSL)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

option(PRIVMX_BUILD_CLI "Building privmxcli client" OFF)
option(PRIVMX_BUILD_BENCHMARK "Building privmxBenchmark client" OFF)
option(PRIVMX_CLI_IMPORTED_LIBRARIES "Using CLI imported libraries" OFF)
option(PRIVMX_IMPORTED_LIBRARIES "Using imported libraries" OFF)
option(PRIVMX_ENABLE_TESTS "Enable tests" OFF)
option(PRIVMX_BUILD_ENDPOINT "Build endpoint lib" OFF)
option(PRIVMX_ENABLE_TESTS_E2E "Enable End to End tests" OFF)
option(PRIVMX_BUILD_DEBUG "Enable extra debug data for lib" OFF)

option(PRIVMX_EMSCRIPTEN "Enable emscripten build" OFF)
message(STATUS "Enable emscripten build - PRIVMX_EMSCRIPTEN=${PRIVMX_EMSCRIPTEN}")

option(PRIVMX_CONAN "Conan build" OFF)
message(STATUS "Conan build - PRIVMX_CONAN=${PRIVMX_CONAN}")

option(PRIVMX_INSTALL_PRIVATE_HEADERS ON)
message(STATUS "Install private header files - PRIVMX_INSTALL_PRIVATE_HEADERS=${PRIVMX_INSTALL_PRIVATE_HEADERS}")

add_compile_options(-Os)

if(PRIVMX_EMSCRIPTEN)
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # Emscripten specific build options
    add_compile_options(-pthread -fexceptions)
    add_link_options(-lembind -lpthread -lwebsocket.js)
    set(PRIVMX_INSTALL_PRIVATE_HEADERS ON)
endif()

if(PRIVMX_CONAN)
    set(PRIVMX_INSTALL_PRIVATE_HEADERS OFF)
endif()

if(PRIVMX_CI_BUILD)
    set(PRIVMX_BUILD_ALL ON)
    set(PRIVMX_ENABLE_TESTS ON)
endif()

if(PRIVMX_CI_WERROR)
    set(PRIVMX_WERROR ON)
endif()

if(PRIVMX_BUILD_ALL)
    set(PRIVMX_BUILD_CLI ON)
    set(PRIVMX_BUILD_ENDPOINT ON)
endif()

if(PRIVMX_BUILD_ENDPOINT)
    #set(PRIVMX_BUILD_STORE ON)
endif()

# For CLI programs pocket required
if(PRIVMX_BUILD_CLI)
    set(PRIVMX_BUILD_POCKET ON)
endif()

# Fix for PRIVMX_ENABLE_TESTS_E2E
if(PRIVMX_ENABLE_TESTS_E2E)
    set(PRIVMX_BUILD_ENDPOINT ON)
endif()

message(STATUS "Using CLI imported libraries - PRIVMX_CLI_IMPORTED_LIBRARIES=${PRIVMX_CLI_IMPORTED_LIBRARIES}")
message(STATUS "Building privmxcli client - PRIVMX_BUILD_CLI=${PRIVMX_BUILD_CLI}")
message(STATUS "Building privmxBenchmark client - PRIVMX_BUILD_BENCHMARK=${PRIVMX_BUILD_BENCHMARK}")

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)

message(STATUS "Using imported libraries - PRIVMX_IMPORTED_LIBRARIES=${PRIVMX_IMPORTED_LIBRARIES}")
if(PRIVMX_IMPORTED_LIBRARIES)
    add_library(PocoFoundation SHARED IMPORTED GLOBAL)
    add_library(PocoJSON SHARED IMPORTED GLOBAL)
    set_property(TARGET PocoFoundation PROPERTY IMPORTED_LOCATION ${PRIVMX_POCO_FOUNDATION})
    set_property(TARGET PocoJSON PROPERTY IMPORTED_LOCATION ${PRIVMX_POCO_JSON})
    add_library(Poco::Foundation ALIAS PocoFoundation)
    add_library(Poco::JSON ALIAS PocoJSON)
    include_directories(${PRIVMX_POCO_INCLUDES})
    if(PRIVMX_PSON)
        add_library(Pson SHARED IMPORTED GLOBAL)
        set_property(TARGET Pson PROPERTY IMPORTED_LOCATION ${PRIVMX_PSON})
        include_directories(${PRIVMX_PSON_INCLUDES})
    endif(PRIVMX_PSON)
    if(PRIVMX_GMP)
        add_library(gmp SHARED IMPORTED GLOBAL)
        set_property(TARGET gmp PROPERTY IMPORTED_LOCATION ${PRIVMX_GMP})
        include_directories(${PRIVMX_GMP_INCLUDES})
    endif(PRIVMX_GMP)
    if(PRIVMX_BUILD_CLI AND PRIVMX_CLI_READLINE)
        add_library(readline SHARED IMPORTED GLOBAL)
        set_property(TARGET readline PROPERTY IMPORTED_LOCATION ${PRIVMX_CLI_READLINE})
        include_directories(${PRIVMX_CLI_READLINE_INCLUDES})
    endif(PRIVMX_BUILD_CLI AND PRIVMX_CLI_READLINE)
    if(PRIVMX_DRVCRYPTO)
        add_library(privmxdrvcrypto SHARED IMPORTED GLOBAL)
        set_property(TARGET privmxdrvcrypto PROPERTY IMPORTED_LOCATION ${PRIVMX_DRVCRYPTO})
        include_directories(${PRIVMX_DRVCRYPTO_INCLUDES})
    endif(PRIVMX_DRVCRYPTO)
    if(PRIVMX_DRVECC)
        add_library(privmxdrvecc SHARED IMPORTED GLOBAL)
        set_property(TARGET privmxdrvecc PROPERTY IMPORTED_LOCATION ${PRIVMX_DRVECC})
        include_directories(${PRIVMX_DRVECC_INCLUDES})
    endif(PRIVMX_DRVECC)
    if(PRIVMX_DRVNET)
        add_library(privmxdrvnet SHARED IMPORTED GLOBAL)
        set_property(TARGET privmxdrvnet PROPERTY IMPORTED_LOCATION ${PRIVMX_DRVNET})
        include_directories(${PRIVMX_DRVNET_INCLUDES})
    endif(PRIVMX_DRVNET)
    if(NOT PRIVMX_EMSCRIPTEN) # tmp fix
        add_library(PocoNet SHARED IMPORTED GLOBAL)
        add_library(PocoNetSSL SHARED IMPORTED GLOBAL)
        add_library(PocoCrypto SHARED IMPORTED GLOBAL)
        set_property(TARGET PocoNet PROPERTY IMPORTED_LOCATION ${PRIVMX_POCO_NET})
        set_property(TARGET PocoNetSSL PROPERTY IMPORTED_LOCATION ${PRIVMX_POCO_NETSSL})
        set_property(TARGET PocoCrypto PROPERTY IMPORTED_LOCATION ${PRIVMX_POCO_CRYPTO})
        add_library(Poco::Net ALIAS PocoNet)
        add_library(Poco::NetSSL ALIAS PocoNetSSL)
        add_library(Poco::Crypto ALIAS PocoCrypto)
    endif()
    if(PRIVMX_OPENSSL_CRYPTO)
        add_library(crypto SHARED IMPORTED GLOBAL)
        set_property(TARGET crypto PROPERTY IMPORTED_LOCATION ${PRIVMX_OPENSSL_CRYPTO})
        add_library(OpenSSL::Crypto ALIAS crypto)
        include_directories(${PRIVMX_OPENSSL_INCLUDES})
    endif(PRIVMX_OPENSSL_CRYPTO)
else(PRIVMX_IMPORTED_LIBRARIES)
    if(NOT PRIVMX_EMSCRIPTEN) # tmp fix
        find_package(OpenSSL)
        find_package(Poco REQUIRED COMPONENTS Foundation JSON)
        find_package(Poco REQUIRED COMPONENTS Net NetSSL Crypto)
    else()
        find_package(Poco REQUIRED COMPONENTS Foundation JSON)
    endif()
endif(PRIVMX_IMPORTED_LIBRARIES)
find_package(Threads REQUIRED)
if(PRIVMX_CONAN)
    find_package(Pson REQUIRED)
    add_library(Pson ALIAS pson::Pson)
    find_package(gmp REQUIRED)
    add_library(gmp ALIAS gmp::gmp)
    if(PRIVMX_DRIVER_CRYPTO)
        find_package(privmxdrvcrypto REQUIRED)
        add_library(privmxdrvcrypto ALIAS privmxdrvcrypto::privmxdrvcrypto)
        find_package(privmxdrvecc REQUIRED)
        add_library(privmxdrvecc ALIAS privmxdrvecc::privmxdrvecc)
    endif()
    if(PRIVMX_DRIVER_NET)
        find_package(privmxdrvnet REQUIRED)
        add_library(privmxdrvnet ALIAS privmxdrvnet::privmxdrvnet)
    endif()
    if(PRIVMX_BUILD_CLI)
        find_package(readline REQUIRED)
        add_library(readline ALIAS readline::readline)
    endif()
    if(PRIVMX_ENABLE_TESTS) 
        find_package(GTest REQUIRED)
        add_library(Gtest ALIAS gtest::gtest)
    endif()
endif()

message(STATUS "Enable tests - PRIVMX_ENABLE_TESTS=${PRIVMX_ENABLE_TESTS}")
message(STATUS "Enable tests_e2e - PRIVMX_ENABLE_TESTS_E2E=${PRIVMX_ENABLE_TESTS_E2E}")

if(PRIVMX_ENABLE_TESTS)
    include(FindGTest)
    include(GoogleTest)
    enable_testing()
endif()


add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(rpc)
add_subdirectory(privfs)
message(STATUS "Build enpoint - PRIVMX_BUILD_ENDPOINT=${PRIVMX_BUILD_ENDPOINT}")
if(PRIVMX_BUILD_ENDPOINT)
    add_subdirectory(endpoint)
    set_target_properties(privmx PROPERTIES COMPILE_DEFINITIONS "MINIMAL_BUILD")
endif()

if(PRIVMX_BUILD_DEBUG_APPS)
    add_subdirectory(__DEBUG)
    set_target_properties(privmx PROPERTIES COMPILE_DEFINITIONS "MINIMAL_BUILD")
endif()