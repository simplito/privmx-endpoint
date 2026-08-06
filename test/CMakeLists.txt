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
# Inbox
add_executable(test_e2e_InboxTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxTest.cpp)
target_link_libraries(test_e2e_InboxTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_InboxModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxModuleEventsTest.cpp)
target_link_libraries(test_e2e_InboxModuleEventsTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
# Event
add_executable(test_e2e_EventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/EventsTest.cpp)
target_link_libraries(test_e2e_EventsTest privmx privmxendpointcore privmxendpointevent Poco::Foundation Poco::Util GTest::GTest)
# Other
add_executable(test_e2e_CryptoTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CryptoTest.cpp)
target_link_libraries(test_e2e_CryptoTest privmx privmxendpointcore privmxendpointcrypto Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_UtilsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/UtilsTest.cpp)
target_link_libraries(test_e2e_UtilsTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
# Kvdb
add_executable(test_e2e_KvdbTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbTest.cpp)
target_link_libraries(test_e2e_KvdbTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_KvdbModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbModuleEventsTest.cpp)
target_link_libraries(test_e2e_KvdbModuleEventsTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
# Group
add_executable(test_e2e_GroupTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/GroupTest.cpp)
target_link_libraries(test_e2e_GroupTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_ThreadUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/ThreadUsingGroupsTest.cpp)
target_link_libraries(test_e2e_ThreadUsingGroupsTest privmx privmxendpointcore privmxendpointthread privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)

## UNIT TESTS
# These need no server, no docker and no network. They compile the source under test directly instead of
# linking the module library, so they stay fast and independent of the rest of the build.
#
# The key-tree arithmetic must agree exactly with the bridge's implementation — the server performs the same
# computation to decide which nodes a removal is obliged to refresh. `tools/keytree_conformance_dump.cpp`
# emits the vectors used to diff the two; see test/tools/README.md.
add_executable(test_unit_TreeMathTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeMathTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
)
target_include_directories(test_unit_TreeMathTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_TreeMathTest GTest::GTest GTest::Main)

add_executable(test_unit_LadderMathTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/LadderMathTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderMath.cpp
)
target_include_directories(test_unit_LadderMathTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_LadderMathTest GTest::GTest GTest::Main)

# Unlike the two above, this one exercises real EC keys and real ECIES, so it links the crypto stack. Still no
# server, no docker and no network: it builds trees, climbs them and removes members entirely in-process.
add_executable(test_unit_TreeKeysTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeKeysTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
)
target_include_directories(test_unit_TreeKeysTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_TreeKeysTest privmx Poco::Foundation GTest::GTest GTest::Main)

add_executable(test_unit_LadderKeysTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/LadderKeysTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
)
target_include_directories(test_unit_LadderKeysTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_LadderKeysTest privmx Poco::Foundation GTest::GTest GTest::Main)

# Goes through the wire types (`server::GroupInfo`), which is where the tree and the ladder meet the server API
# and therefore where a field mismatch would hide. Needs the core module for the JSON struct machinery.
add_executable(test_unit_GroupKeyResolverTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/GroupKeyResolverTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/GroupKeyResolver.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
)
target_include_directories(test_unit_GroupKeyResolverTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_GroupKeyResolverTest privmx privmxendpointcore Poco::Foundation GTest::GTest GTest::Main)

# The merge from plans to a complete submitted state. Real EC keys, and each state is climbed to prove that the
# members who should still have access do — a state the server would accept but nobody can climb is worse than
# one it rejects.
add_executable(test_unit_TreeWireTest
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeWireTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeWire.cpp
)
target_include_directories(test_unit_TreeWireTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(test_unit_TreeWireTest privmx privmxendpointcore Poco::Foundation GTest::GTest GTest::Main)

# Emits the tree states this client produces, for the bridge's validator to run against. See test/tools/README.md.
add_executable(keytree_state_dump
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/keytree_state_dump.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeKeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeWire.cpp
)
target_include_directories(keytree_state_dump PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
target_link_libraries(keytree_state_dump privmx privmxendpointcore Poco::Foundation)

# Emits the conformance vectors for the cross-implementation diff. Not a test; a tool.
add_executable(keytree_conformance_dump
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/keytree_conformance_dump.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/TreeMath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/src/keytree/LadderMath.cpp
)
target_include_directories(keytree_conformance_dump PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../endpoint/group/include)
# StreamLow
add_executable(test_e2e_StreamLowTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StreamLowTest.cpp)
target_link_libraries(test_e2e_StreamLowTest privmx privmxendpointcore privmxendpointstream Poco::Foundation Poco::Util GTest::GTest GTest::Main)
# Stream low-level events (room lifecycle + subscribe/unsubscribe contract, no WebRTC required)
add_executable(test_e2e_StreamEventsLowTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StreamEventsLowTest.cpp)
target_link_libraries(test_e2e_StreamEventsLowTest privmx privmxendpointcore privmxendpointstream Poco::Foundation Poco::Util GTest::GTest GTest::Main)

# Standalone DataChannel wire-format golden-vector tool 
# DataChannel wire format against the TS implementation.
add_executable(datachannel_vector_tool ${CMAKE_CURRENT_SOURCE_DIR}/tools/datachannel_vector_tool.cpp)
target_link_libraries(datachannel_vector_tool privmx privmxendpointcore privmxendpointstream)

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
    add_executable(test_e2e_StreamEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StreamEventsTest.cpp)
    target_link_libraries(test_e2e_StreamEventsTest privmx privmxendpointcore privmxendpointstream privmxendpointstream_webrtc libwebrtc Poco::Foundation Poco::Util GTest::GTest GTest::Main)
    # Live E2E DataChannel interop client driven
    # RTCDataChannel interop over a real connection.
    add_executable(datachannel_interop_client ${CMAKE_CURRENT_SOURCE_DIR}/tools/datachannel_interop_client.cpp)
    target_link_libraries(datachannel_interop_client privmx privmxendpointcore privmxendpointstream privmxendpointstream_webrtc libwebrtc)
    endif()

## Docker Setup
add_executable(test_env_DockerSetupData ${CMAKE_CURRENT_SOURCE_DIR}/test_env/utils/DockerSetupData.cpp)
target_link_libraries(test_env_DockerSetupData privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointevent privmxendpointkvdb privmxendpointgroup Poco::Foundation Poco::Util)
