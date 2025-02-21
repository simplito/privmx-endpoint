file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(INCLUDE_PUB_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include_pub)

add_library(libwebrtc SHARED IMPORTED)
set_target_properties(libwebrtc PROPERTIES
    IMPORTED_LOCATION "<path_to_libwebrtc>"
    INTERFACE_INCLUDE_DIRECTORIES "<path_to_libwebrtc>"
)

add_library(privmxendpointstream_webrtc OBJECT ${SOURCES})
target_include_directories(privmxendpointstream_webrtc PUBLIC ${INCLUDE_DIRS} PUBLIC ${INCLUDE_PUB_DIRS})
target_compile_options(privmxendpointstream_webrtc PRIVATE -fPIC -Wall -Wextra)
target_link_libraries(privmxendpointstream_webrtc PRIVATE Poco::Foundation privmx privmxendpointcore privmxendpointevent privmxendpointstream_stream libwebrtc)
if(BUILD_SHARED_LIBS)
    set_target_properties(privmxendpointstream_webrtc PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include_pub/privmx DESTINATION include)
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/privmx DESTINATION include)
endif()
if(PRIVMX_WERROR)
    target_compile_options(privmxendpointstream_webrtc PRIVATE -Werror)
endif()
set_target_properties(privmxendpointstream_webrtc PROPERTIES COMPILE_DEFINITIONS "MINIMAL_BUILD")
