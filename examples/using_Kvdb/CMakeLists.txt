cmake_minimum_required(VERSION 3.15)
project(using_Kvdb)
set(CMAKE_CXX_STANDARD 17)

find_package(privmxendpoint REQUIRED)

set(SOURCES main.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} PUBLIC 
	privmxendpoint::privmxendpointcore 
	privmxendpoint::privmxendpointkvdb
)