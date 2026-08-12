cmake_minimum_required(VERSION 3.12) # >= 3.12 is necessary for C++20
project(NewCryptoProvider VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20) # C++ is necessary for std::span, std::uint8_t, etc.
#set_property(TARGET tgt PROPERTY CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
# find_package(gmp REQUIRED)
find_package(Poco REQUIRED)

file(GLOB_RECURSE BASEFILES ${CMAKE_CURRENT_SOURCE_DIR}/base/src/*.cpp)

file(GLOB_RECURSE LIBRARYFROMOPENSSL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromOpenssl/src/*.cpp)
file(GLOB_RECURSE LIBRARYFROMDRIVER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromDriver/src/*.cpp)


set(PROJECT_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/base/include ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromOpenssl/include ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromDriver/include)
set(INCLUDE_LIBOPENSSL ${CMAKE_CURRENT_SOURCE_DIR}/base/include ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromOpenssl/include)
set(INCLUDE_LIBDRIVER ${CMAKE_CURRENT_SOURCE_DIR}/base/include ${CMAKE_CURRENT_SOURCE_DIR}/CryptoProviderFromDriver/include)

add_library(libraryFromOpenssl STATIC ${BASEFILES} ${LIBRARYFROMOPENSSL_FILES})
target_include_directories(libraryFromOpenssl PUBLIC ${INCLUDE_LIBOPENSSL})
target_link_libraries(libraryFromOpenssl
    PRIVATE
        Poco::Poco)


add_library(libraryFromDriver STATIC ${BASEFILES} ${LIBRARYFROMDRIVER_FILES})
target_include_directories(libraryFromDriver PUBLIC ${INCLUDE_LIBDRIVER})
target_link_libraries(libraryFromDriver
    PRIVATE
        openssl::openssl)


#add_library(${PROJECT_NAME} STATIC ${BASEFILES} ${LIBRARYFROMDRIVER_FILES})
#add_library(${PROJECT_NAME} STATIC ${BASEFILES})
add_library(${PROJECT_NAME} STATIC ${BASEFILES} ${LIBRARYFROMOPENSSL_FILES} ${LIBRARYFROMDRIVER_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_LIBDRIVER}  ${INCLUDE_LIBOPENSSL})
target_link_libraries(${PROJECT_NAME}
    # PUBLIC
    #     libraryFromDriver libraryFromOpenssl
    PRIVATE
        Poco::Poco
        openssl::openssl)


######    ONLY FOR TEMPORARY TESTING     #####
add_executable(${PROJECT_NAME}-exec src/main.cpp)
target_include_directories(${PROJECT_NAME}-exec 
    PUBLIC 
#        ${INCLUDE_LIBOPENSSL}
#        ${INCLUDE_LIBDRIVER}
        ${PROJECT_INCLUDE}
        )
target_link_libraries(${PROJECT_NAME}-exec
    PRIVATE         
        ${PROJECT_NAME})
