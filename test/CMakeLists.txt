cmake_minimum_required(VERSION 3.10.2)

option(PRIVMX_CONAN "Conan build" OFF)
message(STATUS "Conan build - PRIVMX_CONAN=${PRIVMX_CONAN}")

project(privmx_e2e)

find_package(GTest REQUIRED)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/utils/startTest.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/utils/env.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/utils ${CMAKE_CURRENT_BINARY_DIR}/utils)

## MODULES
# Core
add_executable(test_e2e_CoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CoreTest.cpp)
target_link_libraries(test_e2e_CoreTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_CoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CoreModuleEventsTest.cpp)
target_link_libraries(test_e2e_CoreModuleEventsTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
# Thread
add_executable(test_e2e_ThreadTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/ThreadTest.cpp)
target_link_libraries(test_e2e_ThreadTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_ThreadModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/ThreadModuleEventsTest.cpp)
target_link_libraries(test_e2e_ThreadModuleEventsTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util GTest::GTest)
# Store
add_executable(test_e2e_StoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StoreTest.cpp)
target_link_libraries(test_e2e_StoreTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_StoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StoreModuleEventsTest.cpp)
target_link_libraries(test_e2e_StoreModuleEventsTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util GTest::GTest)
# # Inbox
add_executable(test_e2e_InboxTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxTest.cpp)
target_link_libraries(test_e2e_InboxTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_InboxModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxModuleEventsTest.cpp)
target_link_libraries(test_e2e_InboxModuleEventsTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
# # Event
add_executable(test_e2e_EventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/EventsTest.cpp)
target_link_libraries(test_e2e_EventsTest privmx privmxendpointcore privmxendpointevent Poco::Foundation Poco::Util GTest::GTest)
# # Other
add_executable(test_e2e_CryptoTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CryptoTest.cpp)
target_link_libraries(test_e2e_CryptoTest privmx privmxendpointcore privmxendpointcrypto Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_UtilsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/UtilsTest.cpp)
target_link_libraries(test_e2e_UtilsTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
# # Kvdb
add_executable(test_e2e_KvdbTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbTest.cpp)
target_link_libraries(test_e2e_KvdbTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_KvdbModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbModuleEventsTest.cpp)
target_link_libraries(test_e2e_KvdbModuleEventsTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
# StreamLow
add_executable(test_e2e_StreamLowTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StreamLowTest.cpp)
target_link_libraries(test_e2e_StreamLowTest privmx privmxendpointcore privmxendpointstream Poco::Foundation Poco::Util GTest::GTest GTest::Main)

if(PRIVMX_BUILD_WITH_WEBRTC)
    if(PRIVMX_IMPORT_LIBWEBRTC)
        add_library(libwebrtc SHARED IMPORTED)
        set_target_properties(libwebrtc PROPERTIES
            IMPORTED_LOCATION ${PRIVMX_LIBWEBRTC}
            INTERFACE_INCLUDE_DIRECTORIES ${PRIVMX_LIBWEBRTC_INCLUDE}
        )
    else()
        find_package(libwebrtc REQUIRED CONFIG)
        if(PRIVMX_CONAN)
            add_library(libwebrtc ALIAS libwebrtc::libwebrtc)
        endif()
    endif()
    # Stream
    add_executable(test_e2e_StreamTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StreamTest.cpp)
    target_link_libraries(test_e2e_StreamTest privmx privmxendpointcore privmxendpointstream privmxendpointstream_webrtc libwebrtc Poco::Foundation Poco::Util GTest::GTest GTest::Main)
    endif()

## Docker Setup
add_executable(test_env_DockerSetupData ${CMAKE_CURRENT_SOURCE_DIR}/test_env/utils/DockerSetupData.cpp)
target_link_libraries(test_env_DockerSetupData privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointevent privmxendpointkvdb Poco::Foundation Poco::Util)
