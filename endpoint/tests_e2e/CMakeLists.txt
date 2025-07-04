# add_executable(privmxcontact_test_ThreadService ${CMAKE_CURRENT_SOURCE_DIR}/test1.cpp)
# target_link_libraries(privmxcontact_test_ThreadService PUBLIC Poco::Foundation Poco::JSON Poco::Net Poco::NetSSL Poco::Crypto Pson OpenSSL::Crypto gmp privmx privmxcontact)

find_package(GTest REQUIRED)
target_include_directories(privmx PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointcrypto PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointevent PUBLIC ${INCLUDE_DIRS})
target_include_directories(privmxendpointkvdb PUBLIC ${INCLUDE_DIRS})


file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/utils/startTest.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/utils/env.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/utils ${CMAKE_CURRENT_BINARY_DIR}/utils)

# # MODULES
# Core
add_executable(privmxplatform_test_e2e_CoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CoreTest.cpp)
target_link_libraries(privmxplatform_test_e2e_CoreTest privmx privmxendpointcore Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main privmxdrvcrypto)
add_executable(privmxplatform_test_e2e_CoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CoreModuleEventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_CoreModuleEventsTest privmx privmxendpointcore Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main privmxdrvcrypto)
# Thread
add_executable(privmxplatform_test_e2e_ThreadTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/ThreadTest.cpp)
target_link_libraries(privmxplatform_test_e2e_ThreadTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
add_executable(privmxplatform_test_e2e_ThreadModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/ThreadModuleEventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_ThreadModuleEventsTest privmx privmxendpointcore privmxendpointthread Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
# Store
add_executable(privmxplatform_test_e2e_StoreTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StoreTest.cpp)
target_link_libraries(privmxplatform_test_e2e_StoreTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
add_executable(privmxplatform_test_e2e_StoreModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/StoreModuleEventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_StoreModuleEventsTest privmx privmxendpointcore privmxendpointstore Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
# Inbox
add_executable(privmxplatform_test_e2e_InboxTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxTest.cpp)
target_link_libraries(privmxplatform_test_e2e_InboxTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
add_executable(privmxplatform_test_e2e_InboxModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/InboxModuleEventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_InboxModuleEventsTest privmx privmxendpointcore privmxendpointthread privmxendpointstore privmxendpointinbox Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
# Event
add_executable(privmxplatform_test_e2e_EventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/EventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_EventsTest privmx privmxendpointcore privmxendpointevent Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
# Other
add_executable(privmxplatform_test_e2e_CryptoTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/CryptoTest.cpp)
target_link_libraries(privmxplatform_test_e2e_CryptoTest privmx privmxendpointcore privmxendpointcrypto Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
add_executable(privmxplatform_test_e2e_UtilsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/UtilsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_UtilsTest privmx privmxendpointcore Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
# Kvdb
add_executable(privmxplatform_test_e2e_KvdbTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbTest.cpp)
target_link_libraries(privmxplatform_test_e2e_KvdbTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
add_executable(privmxplatform_test_e2e_KvdbModuleEventsTest ${CMAKE_CURRENT_SOURCE_DIR}/tests/KvdbModuleEventsTest.cpp)
target_link_libraries(privmxplatform_test_e2e_KvdbModuleEventsTest privmx privmxendpointcore privmxendpointkvdb Poco::Foundation Poco::Util Threads::Threads GTest::GTest GTest::Main)
## Docker Setup
add_executable(privmxplatform_test_e2e_DockerSetupData ${CMAKE_CURRENT_SOURCE_DIR}/test_env/create_docker/DockerSetupData.cpp)
target_link_libraries(privmxplatform_test_e2e_DockerSetupData privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointevent privmxendpointkvdb Poco::Foundation Poco::Util Threads::Threads)