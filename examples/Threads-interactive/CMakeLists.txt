cmake_minimum_required(VERSION 3.15)
project(threads_interactive)
set(CMAKE_CXX_STANDARD 17)

find_package(privmxendpoint REQUIRED)
find_package(Curses REQUIRED)
# include_directories(${CURSES_INCLUDE_DIR})

set(SOURCES main.cpp utils.cpp utils.hpp)
add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} PUBLIC 
		privmxendpoint::privmxendpointcore 
		privmxendpoint::privmxendpointthread
		Curses::Curses
)