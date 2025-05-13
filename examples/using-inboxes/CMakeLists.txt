cmake_minimum_required(VERSION 3.15)
project(using_inboxes)
set(CMAKE_CXX_STANDARD 17)

find_package(privmxendpoint REQUIRED)

add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC 
		privmxendpoint::privmxendpointcore
		privmxendpoint::privmxendpointthread
		privmxendpoint::privmxendpointstore
		privmxendpoint::privmxendpointinbox
)