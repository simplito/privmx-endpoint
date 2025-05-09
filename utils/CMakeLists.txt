if(${PRIVMX_BUILD_DEBUG} MATCHES "FULL")
    set(PRIVMX_USE_DEBUG ON)
    set(PRIVMX_DEBUG_TIME ON)
    set(PRIVMX_DEBUG_OUTPUT_TIMESTAMP_ON_START ON)
elseif(PRIVMX_BUILD_DEBUG)
    set(PRIVMX_USE_DEBUG ON)
    set(PRIVMX_DEBUG_TIME OFF)
    set(PRIVMX_DEBUG_OUTPUT_TIMESTAMP_ON_START OFF)
endif()
message(STATUS "Enable utils debug - PRIVMX_BUILD_DEBUG=${PRIVMX_BUILD_DEBUG}")
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/include)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/privmx/utils/DebugConfig.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/utils/DebugConfig.hpp @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/privmx/utils/DebugConfig.hpp DESTINATION include/privmx/utils)

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp)
add_library(privmxutils OBJECT ${SOURCES})
target_include_directories(privmxutils PUBLIC ${INCLUDE_DIRS})
target_compile_options(privmxutils PRIVATE -fPIC -Wall -Wextra -Wno-narrowing)
target_link_libraries(privmxutils PUBLIC Poco::Foundation Poco::JSON Pson)
if(BUILD_SHARED_LIBS)
    set_target_properties(privmxutils PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()
if(PRIVMX_INSTALL_PRIVATE_HEADERS)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/privmx DESTINATION include)
endif()
if(PRIVMX_WERROR)
    target_compile_options(privmxutils PRIVATE -Werror)
endif()
