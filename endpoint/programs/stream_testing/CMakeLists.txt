# target_include_directories(privmx PRIVATE ${INCLUDE_DIRS})

target_include_directories(privmxendpointcrypto PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstream PRIVATE ${INCLUDE_DIRS})

add_library(libwebrtc SHARED IMPORTED) # or STATIC instead of SHARED
set_target_properties(libwebrtc PROPERTIES
  IMPORTED_LOCATION "<path_to_webrtc>/webrtc/src/out-debug/Linux-x64/libwebrtc.so"
  INTERFACE_INCLUDE_DIRECTORIES "<path_to_webrtc>/webrtc/src/libwebrtc/include/"
)

# # MODULES
add_executable(streamsProgram ${CMAKE_CURRENT_SOURCE_DIR}/streams_program.cpp)
target_link_libraries(streamsProgram privmx privmxendpointcore privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointstream libwebrtc)

# # for debuging
# valgrind
# /usr/bin/time -v
