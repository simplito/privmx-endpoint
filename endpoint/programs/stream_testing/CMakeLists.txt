target_include_directories(privmxendpointcrypto PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointcore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointevent PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointthread PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointstore PRIVATE ${INCLUDE_DIRS})
target_include_directories(privmxendpointinbox PRIVATE ${INCLUDE_DIRS})
add_library(libwebrtc SHARED IMPORTED) # or STATIC instead of SHARED
set_target_properties(libwebrtc PROPERTIES
    IMPORTED_LOCATION "<path_to_libwebrtc>"
    INTERFACE_INCLUDE_DIRECTORIES "<path_to_libwebrtc>"
)
target_include_directories(privmxendpointstream PRIVATE ${INCLUDE_DIRS})

# privmxendpointstream
add_executable(streamsProgram2 ${CMAKE_CURRENT_SOURCE_DIR}/streams_program_2.cpp)
target_link_libraries(streamsProgram2 privmx privmxendpointcore privmxendpointcrypto privmxendpointevent privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointstream libwebrtc)

# privmxendpointstream + SDL2
find_package(SDL2 REQUIRED)
add_executable(streamsProgram3 ${CMAKE_CURRENT_SOURCE_DIR}/streams_program_3.cpp)
target_link_libraries(streamsProgram3 SDL2 privmx privmxendpointcore privmxendpointcrypto privmxendpointevent privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointstream libwebrtc)
add_executable(streamsProgram3_b ${CMAKE_CURRENT_SOURCE_DIR}/streams_program_3_b.cpp)
target_link_libraries(streamsProgram3_b SDL2 privmx privmxendpointcore privmxendpointcrypto privmxendpointevent privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointstream libwebrtc)



# privmxendpointstream + wxWidgets
find_package(wxWidgets COMPONENTS core base xrc aui REQUIRED)
if(wxWidgets_USE_FILE) # not defined in CONFIG mode
    include(${wxWidgets_USE_FILE})
endif()
add_executable(streamsProgram4 ${CMAKE_CURRENT_SOURCE_DIR}/streams_program_4.cpp)
target_link_libraries(streamsProgram4 ${wxWidgets_LIBRARIES} privmx privmxendpointcore privmxendpointevent privmxendpointcrypto privmxendpointthread privmxendpointstore privmxendpointinbox privmxendpointstream libwebrtc)
