target_include_directories(privmxendpointcrypto PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointevent PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PRIVATE ${INCLUDE_DIRS})
add_library(libwebrtc SHARED IMPORTED) # or STATIC instead of SHARED
set_target_properties(libwebrtc PROPERTIES
    IMPORTED_LOCATION "/home/zurek/projects/simplito/webrtc/libwebrtc2/webrtc/src/out/Linux-x64/libwebrtc.so"
    INTERFACE_INCLUDE_DIRECTORIES "/home/zurek/projects/simplito/webrtc/libwebrtc2/webrtc/src/libwebrtc/include"
)
target_include_directories(privmxendpointstream PRIVATE ${INCLUDE_DIRS})

find_package(wxWidgets COMPONENTS core base xrc aui REQUIRED)
if(wxWidgets_USE_FILE) # not defined in CONFIG mode
    include(${wxWidgets_USE_FILE})
endif()

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(streamsSample ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp ${SOURCES})
target_include_directories(streamsSample PUBLIC ${INCLUDE_DIRS})
target_link_libraries(streamsSample privmx privmxendpointcore privmxendpointcrypto privmxendpointevent privmxendpointstream Poco::Foundation Poco::Util)
