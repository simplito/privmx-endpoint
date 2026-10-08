file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(INCLUDE_PUB_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include_pub)

if(BUILD_SHARED_LIBS)
    add_library(privmxendpointstore SHARED ${SOURCES})
else()
    add_library(privmxendpointstore STATIC ${SOURCES})
endif()
target_include_directories(privmxendpointstore PUBLIC ${INCLUDE_DIRS} PUBLIC ${INCLUDE_PUB_DIRS})
target_compile_options(privmxendpointstore PRIVATE -fPIC -Wall -Wextra -Wno-narrowing)
# MINIMAL_BUILD trafia tu razem z reszta, bo `set_target_properties(... COMPILE_DEFINITIONS ...)`
# nadpisuje cala wlasciwosc i kasowalo definicje dodane wczesniej. `target_compile_definitions` dokleja.
#
# PRIVMX_DEFAULT_FILE_CIPHER_ID: format zapisu danych pliku. Patrz glowny CMakeLists.
target_compile_definitions(privmxendpointstore
    PRIVATE MINIMAL_BUILD
    PRIVATE PRIVMX_DEFAULT_FILE_CIPHER_ID=${PRIVMX_DEFAULT_FILE_CIPHER_ID})
target_link_libraries(privmxendpointstore PRIVATE Poco::Foundation privmx privmxendpointcore PUBLIC privmxendpointgroup)
if(BUILD_SHARED_LIBS)
    set_target_properties(privmxendpointstore PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()
install(TARGETS privmxendpointstore DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include_pub/privmx DESTINATION include)
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/privmx DESTINATION include)
endif()
if(PRIVMX_WERROR)
    target_compile_options(privmxendpointstore PRIVATE -Werror)
endif()