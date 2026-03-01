cmake_minimum_required(VERSION 3.20)
project(oss-executor VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(OSS_BUILD_TESTS "Build unit tests" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET gtk4)
find_package(CURL    REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)
FetchContent_Declare(Luau
    GIT_REPOSITORY https://github.com/luau-lang/luau.git
    GIT_TAG        0.620
    GIT_SHALLOW    TRUE)
set(LUAU_BUILD_CLI   OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB   OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Luau)

find_package(spdlog 1.12 QUIET CONFIG)
if(NOT spdlog_FOUND)
    FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        v1.13.0
        GIT_SHALLOW    TRUE)
    set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(spdlog)
endif()

find_package(nlohmann_json 3.11 QUIET CONFIG)
if(NOT nlohmann_json_FOUND)
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
    src/utils/http.cpp
    src/utils/logger.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${Luau_SOURCE_DIR}/Compiler/include
    ${Luau_SOURCE_DIR}/Ast/include
    ${Luau_SOURCE_DIR}/VM/include
    ${Luau_SOURCE_DIR}/Common/include
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    APP_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    PkgConfig::GTK4
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    Luau.Compiler
    Luau.Ast
    Luau.VM
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    ${CMAKE_DL_LIBS}
    m
)

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

add_library(oss_payload SHARED src/core/payload.cpp)

target_include_directories(oss_payload PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${Luau_SOURCE_DIR}/Compiler/include
    ${Luau_SOURCE_DIR}/Ast/include
    ${Luau_SOURCE_DIR}/VM/include
    ${Luau_SOURCE_DIR}/Common/include
)

target_link_libraries(oss_payload PRIVATE
    Luau.Compiler
    Luau.Ast
    Luau.VM
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

target_compile_options(oss_payload PRIVATE
    -Wall -Wextra -Wno-unused-parameter
    -O2 -fno-exceptions
)

set_target_properties(oss_payload PROPERTIES
    OUTPUT_NAME               "oss_payload"
    PREFIX                    "lib"
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}"
)

add_dependencies(${PROJECT_NAME} oss_payload)

add_custom_command(TARGET oss_payload POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:oss_payload>
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/$<TARGET_FILE_NAME:oss_payload>)

if(EXISTS ${CMAKE_SOURCE_DIR}/resources)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/resources
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/resources)
endif()

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin)
install(TARGETS oss_payload
    LIBRARY DESTINATION lib/oss-executor)
install(DIRECTORY resources/ DESTINATION share/oss-executor/resources OPTIONAL)
install(DIRECTORY themes/    DESTINATION share/oss-executor/themes    OPTIONAL)
install(DIRECTORY scripts/   DESTINATION share/oss-executor/scripts   OPTIONAL)
install(FILES config.json    DESTINATION share/oss-executor           OPTIONAL)

