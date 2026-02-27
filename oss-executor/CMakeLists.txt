cmake_minimum_required(VERSION 3.16)
project(OSSExecutor VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET gtk4)
pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(LUAJIT REQUIRED IMPORTED_TARGET luajit)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)

find_package(spdlog 1.12 QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found — fetching via FetchContent")
    FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        v1.13.0
        GIT_SHALLOW    TRUE)
    set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(spdlog)
endif()

find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found — fetching via FetchContent")
    FetchContent_Declare(json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE)
    FetchContent_MakeAvailable(json)
endif()

set(SOURCES
    src/main.cpp
    src/core/executor.cpp
    src/core/injection.cpp
    src/core/hooks.cpp
    src/core/lua_engine.cpp
    src/core/memory.cpp
    src/api/closures.cpp
    src/api/environment.cpp
    src/api/quorum_api.cpp
    src/scripting/script_hub.cpp
    src/scripting/script_manager.cpp
    src/ui/app.cpp
    src/ui/console.cpp
    src/ui/editor.cpp
    src/ui/file_dialog.cpp
    src/ui/overlay.cpp
    src/ui/tabs.cpp
    src/ui/theme.cpp
    src/utils/config.cpp
    src/utils/crypto.cpp
    src/utils/logger.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    PkgConfig::GTK4
    PkgConfig::LUAJIT
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    ${CMAKE_DL_LIBS}
    Threads::Threads
    m
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

if(EXISTS ${CMAKE_SOURCE_DIR}/resources)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/resources
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/resources
        COMMENT "Copying resources → build dir")
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY resources/ DESTINATION share/oss-executor/resources OPTIONAL)
install(DIRECTORY themes/    DESTINATION share/oss-executor/themes    OPTIONAL)
install(DIRECTORY scripts/   DESTINATION share/oss-executor/scripts   OPTIONAL)
