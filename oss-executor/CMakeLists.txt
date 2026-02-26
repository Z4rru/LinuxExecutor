cmake_minimum_required(VERSION 3.16)
project(OSSExecutor VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ── Dependencies ──────────────────────────────────────────────

find_package(PkgConfig REQUIRED)

# GTK4
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET gtk4)

# GLib version checks
pkg_check_modules(GLIB REQUIRED glib-2.0)
# ═══════════════════════════════════════════════════════════════
# NOTE: G_APPLICATION_DEFAULT_FLAGS compat (OSS_GLIB_COMPAT)
# removed — app.cpp now uses G_APPLICATION_NON_UNIQUE (GLib 2.30+)
# which is universally available on any system with GTK4.
# ═══════════════════════════════════════════════════════════════
if(GLIB_VERSION VERSION_LESS "2.76")
    message(STATUS
        "GLib ${GLIB_VERSION}: g_task_set_static_name not available.  "
        "GIO_MODULE_DIR will be set to \"\" at runtime to prevent GVFS symbol mismatch."
    )
endif()

# LuaJIT
pkg_check_modules(LUAJIT REQUIRED IMPORTED_TARGET luajit)

# CURL
find_package(CURL REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)

# ══════════════════════════════════════════════════════════════
# ██  FIX: find_package(Threads) MUST come before             ██
# ██  target_link_libraries — Threads::Threads is an          ██
# ██  IMPORTED target that must exist at configure time.       ██
# ██                                                           ██
# ██  BEFORE: find_package(Threads) was 20 lines AFTER the    ██
# ██  target_link_libraries call → CMake CMP0028 error:        ██
# ██  "Target Threads::Threads not found"                      ██
# ══════════════════════════════════════════════════════════════
find_package(Threads REQUIRED)

# ── Optional system packages with FetchContent fallback ───────

include(FetchContent)

# spdlog
find_package(spdlog 1.12 QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found on system — fetching via FetchContent")
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        v1.13.0
        GIT_SHALLOW    TRUE
    )
    set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(spdlog)
endif()

# nlohmann/json
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found on system — fetching via FetchContent")
    FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(json)
endif()

# ── Source Files ──────────────────────────────────────────────

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

# stdc++fs — only needed on GCC < 9
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()

# ── Compiler Warnings ────────────────────────────────────────

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

# ── Post-Build: copy resources ────────────────────────────────

if(EXISTS ${CMAKE_SOURCE_DIR}/resources)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/resources
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/resources
        COMMENT "Copying resources → build dir"
    )
endif()

# ── Install ───────────────────────────────────────────────────

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY resources/ DESTINATION share/oss-executor/resources OPTIONAL)
install(DIRECTORY themes/    DESTINATION share/oss-executor/themes    OPTIONAL)
install(DIRECTORY scripts/   DESTINATION share/oss-executor/scripts   OPTIONAL)
