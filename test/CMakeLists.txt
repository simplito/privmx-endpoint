cmake_minimum_required(VERSION 3.10.2)

option(PRIVMX_CONAN "Conan build" OFF)
message(STATUS "Conan build - PRIVMX_CONAN=${PRIVMX_CONAN}")
project(privmx_testing)

find_package(GTest REQUIRED)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/utils ${CMAKE_CURRENT_BINARY_DIR}/utils)

# Data set Generator
add_executable(test_env_DockerSetupData ${CMAKE_CURRENT_SOURCE_DIR}/test_env/utils/DockerSetupData.cpp)
target_link_libraries(test_env_DockerSetupData privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointevent privmxendpointkvdb privmxendpointlock privmxendpointsearch privmxendpointgroup Poco::Foundation Poco::Util)



## END to End TESTS
# Core
add_executable(test_e2e_CoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/CoreTest.cpp)
target_link_libraries(test_e2e_CoreTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_CoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/CoreModuleEventsTest.cpp)
target_link_libraries(test_e2e_CoreModuleEventsTest privmx privmxendpointcore Poco::Foundation Poco::Util GTest::GTest)
# Thread
add_executable(test_e2e_ThreadTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/ThreadTest.cpp)
target_link_libraries(test_e2e_ThreadTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_ThreadModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/ThreadModuleEventsTest.cpp)
target_link_libraries(test_e2e_ThreadModuleEventsTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util GTest::GTest)
# Store
add_executable(test_e2e_StoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StoreTest.cpp)
target_link_libraries(test_e2e_StoreTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_StoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StoreModuleEventsTest.cpp)
target_link_libraries(test_e2e_StoreModuleEventsTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util GTest::GTest)
# Inbox
add_executable(test_e2e_InboxTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/InboxTest.cpp)
target_link_libraries(test_e2e_InboxTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_InboxModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/InboxModuleEventsTest.cpp)
target_link_libraries(test_e2e_InboxModuleEventsTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util GTest::GTest)
# Event
add_executable(test_e2e_EventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/EventsTest.cpp)
target_link_libraries(test_e2e_EventsTest privmx privmxendpointcore privmxendpointevent Poco::Foundation Poco::Util GTest::GTest)
# Kvdb
add_executable(test_e2e_KvdbTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/KvdbTest.cpp)
target_link_libraries(test_e2e_KvdbTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_KvdbModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/KvdbModuleEventsTest.cpp)
target_link_libraries(test_e2e_KvdbModuleEventsTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util GTest::GTest)
# Group
add_executable(test_e2e_GroupTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/GroupTest.cpp)
target_link_libraries(test_e2e_GroupTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_ThreadUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/ThreadUsingGroupsTest.cpp)
target_link_libraries(test_e2e_ThreadUsingGroupsTest privmx privmxendpointcore privmxendpointthread privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_StoreUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StoreUsingGroupsTest.cpp)
target_link_libraries(test_e2e_StoreUsingGroupsTest privmx privmxendpointcore privmxendpointstore privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_KvdbUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/KvdbUsingGroupsTest.cpp)
target_link_libraries(test_e2e_KvdbUsingGroupsTest privmx privmxendpointcore privmxendpointkvdb privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_InboxUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/InboxUsingGroupsTest.cpp)
target_link_libraries(test_e2e_InboxUsingGroupsTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_StreamRoomUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StreamRoomUsingGroupsTest.cpp)
target_link_libraries(test_e2e_StreamRoomUsingGroupsTest privmx privmxendpointcore privmxendpointstream privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_LockUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/LockUsingGroupsTest.cpp)
target_link_libraries(test_e2e_LockUsingGroupsTest privmx privmxendpointcore privmxendpointstore privmxendpointlock privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_SearchUsingGroupsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/SearchUsingGroupsTest.cpp)
target_link_libraries(test_e2e_SearchUsingGroupsTest privmx privmxendpointcore privmxendpointstore privmxendpointkvdb privmxendpointlock privmxendpointsearch privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# A write the Bridge refuses must not take the Index down with it. Two sessions stay connected at once, so a
# handle can outlive the group epoch it was opened under.
add_executable(test_e2e_SearchGroupRejectedWriteTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/SearchGroupRejectedWriteTest.cpp)
target_link_libraries(test_e2e_SearchGroupRejectedWriteTest privmx privmxendpointcore privmxendpointstore privmxendpointkvdb privmxendpointlock privmxendpointsearch privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# One long Thread+Group flow across a member removal, with three sessions kept alive so their key caches carry over
add_executable(test_e2e_ThreadGroupScenarioTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/ThreadGroupScenarioTest.cpp)
target_link_libraries(test_e2e_ThreadGroupScenarioTest privmx privmxendpointcore privmxendpointthread privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# The same flow for the other container modules; each adds what its own items make possible (file bytes, keyed
# and versioned entries, an Inbox's three containers and its manual re-key)
add_executable(test_e2e_StoreGroupScenarioTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StoreGroupScenarioTest.cpp)
target_link_libraries(test_e2e_StoreGroupScenarioTest privmx privmxendpointcore privmxendpointstore privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_KvdbGroupScenarioTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/KvdbGroupScenarioTest.cpp)
target_link_libraries(test_e2e_KvdbGroupScenarioTest privmx privmxendpointcore privmxendpointkvdb privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
add_executable(test_e2e_InboxGroupScenarioTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/InboxGroupScenarioTest.cpp)
target_link_libraries(test_e2e_InboxGroupScenarioTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# Tree-backed groups end to end (only place the full round trip runs; unit tests and the conformance fixture each cover just one side)
add_executable(test_e2e_GroupKeyTreeTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/GroupKeyTreeTest.cpp)
target_link_libraries(test_e2e_GroupKeyTreeTest privmx privmxendpointcore privmxendpointthread privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# A hostile client against the key tree: a group's key worn as a user's, nested groups, seat churn, a concurrent
# add and remove of one member. Needs the Bridge management API key from the dataset ini to register context users.
add_executable(test_e2e_GroupAbuseTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/GroupAbuseTest.cpp)
target_link_libraries(test_e2e_GroupAbuseTest privmx privmxendpointcore privmxendpointthread privmxendpointgroup Poco::Foundation Poco::Util GTest::GTest)
# Lock
add_executable(test_e2e_LockTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/LockTest.cpp)
target_link_libraries(test_e2e_LockTest privmx privmxendpointcore privmxendpointstore privmxendpointlock Poco::Foundation Poco::Util GTest::GTest)
# Search
add_executable(test_e2e_SearchTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/SearchTest.cpp)
target_link_libraries(test_e2e_SearchTest privmx privmxendpointcore privmxendpointstore privmxendpointkvdb privmxendpointlock privmxendpointsearch Poco::Foundation Poco::Util GTest::GTest GTest::Main)
# StreamLow
add_executable(test_e2e_StreamLowTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StreamLowTest.cpp)
target_link_libraries(test_e2e_StreamLowTest privmx privmxendpointcore privmxendpointstream Poco::Foundation Poco::Util GTest::GTest GTest::Main)
# Stream low-level events (room lifecycle + subscribe/unsubscribe contract, no WebRTC required)
add_executable(test_e2e_StreamEventsLowTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StreamEventsLowTest.cpp)
target_link_libraries(test_e2e_StreamEventsLowTest privmx privmxendpointcore privmxendpointstream Poco::Foundation Poco::Util GTest::GTest GTest::Main)

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
    add_executable(test_e2e_StreamTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StreamTest.cpp)
    target_link_libraries(test_e2e_StreamTest privmx privmxendpointcore privmxendpointstream privmxendpointstream_webrtc libwebrtc Poco::Foundation Poco::Util GTest::GTest GTest::Main)
    add_executable(test_e2e_StreamEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/StreamEventsTest.cpp)
    target_link_libraries(test_e2e_StreamEventsTest privmx privmxendpointcore privmxendpointstream privmxendpointstream_webrtc libwebrtc Poco::Foundation Poco::Util GTest::GTest GTest::Main)
endif()

## UNIT TESTS
# No server, docker, or network needed

add_executable(test_unit_CryptoTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/CryptoTest.cpp)
target_link_libraries(test_unit_CryptoTest privmx privmxendpointcore privmxendpointcrypto Poco::Foundation GTest::GTest GTest::Main)

add_executable(test_unit_UtilsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/UtilsTest.cpp)
target_link_libraries(test_unit_UtilsTest privmx privmxendpointcore Poco::Foundation GTest::GTest GTest::Main)

# Choosing between several group-addressed routes to one container key. Stubs the group key resolver, which is
# the only way to make a route unopenable on demand and to assert that a route was NOT attempted.
add_executable(test_unit_KeyProviderGroupKeysTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/KeyProviderGroupKeysTest.cpp)
target_link_libraries(test_unit_KeyProviderGroupKeysTest privmx privmxendpointcore privmxendpointcrypto Poco::Foundation GTest::GTest GTest::Main)

# Key-tree arithmetic must match the bridge exactly (it computes the same refresh set; keytree_conformance_dump.cpp emits diff vectors, see test/tools/README.md)
add_executable(test_unit_TreeMathTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeMathTest.cpp)
target_link_libraries(test_unit_TreeMathTest privmxendpointgroup GTest::GTest GTest::Main)

add_executable(test_unit_LadderMathTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/LadderMathTest.cpp)
target_link_libraries(test_unit_LadderMathTest privmxendpointgroup GTest::GTest GTest::Main)

# Real EC keys and ECIES (builds, climbs, and removes members from trees entirely in-process; still no server/docker/network)
add_executable(test_unit_TreeKeysTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeKeysTest.cpp)
target_link_libraries(test_unit_TreeKeysTest privmx privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

add_executable(test_unit_LadderKeysTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/LadderKeysTest.cpp)
target_link_libraries(test_unit_LadderKeysTest privmx privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

# Goes through the wire types (server::GroupInfo, where tree and ladder meet the server API; needs core for JSON struct machinery)
add_executable(test_unit_GroupKeyResolverTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/GroupKeyResolverTest.cpp)
target_link_libraries(test_unit_GroupKeyResolverTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

# Roster attestation and the monotone version pin (builds signed server::GroupInfo by hand via GroupDataSchemaMapper::encrypt, no live bridge)
add_executable(test_unit_GroupRosterTagTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/GroupRosterTagTest.cpp)
target_link_libraries(test_unit_GroupRosterTagTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

# Format-only roster validation (that "format only" still refuses malformed keys)
add_executable(test_unit_RosterValidatorTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/RosterValidatorTest.cpp)
target_link_libraries(test_unit_RosterValidatorTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

# Merge from plans to a complete submitted state (real EC keys; each state is climbed to prove members who should still have access do)
add_executable(test_unit_TreeWireTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/TreeWireTest.cpp)
target_link_libraries(test_unit_TreeWireTest privmx privmxendpointcore privmxendpointgroup Poco::Foundation GTest::GTest GTest::Main)

# Emits the tree states this client produces (for the bridge's validator to run against; see test/tools/README.md)
add_executable(keytree_state_dump ${CMAKE_CURRENT_SOURCE_DIR}/tools/keytree_state_dump.cpp)
target_link_libraries(keytree_state_dump privmx privmxendpointcore privmxendpointgroup Poco::Foundation)

# Emits the conformance vectors for the cross-implementation diff (not a test, a tool)
add_executable(keytree_conformance_dump ${CMAKE_CURRENT_SOURCE_DIR}/tools/keytree_conformance_dump.cpp)
target_link_libraries(keytree_conformance_dump privmxendpointgroup)
