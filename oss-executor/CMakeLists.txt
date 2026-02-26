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

# GLib version checks — prevent hard-to-debug runtime crashes
pkg_check_modules(GLIB REQUIRED glib-2.0)
if(GLIB_VERSION VERSION_LESS "2.74")
    message(WARNING
        "GLib ${GLIB_VERSION} detected.  GLib ≥ 2.74 required for "
        "G_APPLICATION_DEFAULT_FLAGS.  Build will use compatibility fallback."
    )
    add_compile_definitions(OSS_GLIB_COMPAT)
endif()
if(GLIB_VERSION VERSION_LESS "2.76")
    message(STATUS
        "GLib ${GLIB_VERSION}: g_task_set_static_name not available.  "
        "GIO_MODULE_DIR will be set to \"\" at runtime to prevent GVFS symbol mismatch."
    )
endif()

# LuaJIT
pkg_check_modules(LUAJIT REQUIRED IMPORTED_TARGET luajit)

# CURL  (find_package provides proper IMPORTED target)
find_package(CURL REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)

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
    set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)   # use bundled fmt
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

# ── Source Files (explicit — GLOB_RECURSE hides missing files) ─

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
    ${CMAKE_DL_LIBS}           # portable dl
    Threads::Threads           # portable pthreads
    m
)

# Threads::Threads requires this
find_package(Threads REQUIRED)

# stdc++fs — only needed on GCC < 9
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()

# ── Compiler Warnings (target-scoped, never override -O flags) ─

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    -fPIC
)

# ── Post-Build: copy resources next to binary ──────────────────

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
install(DIRECTORY resources/ DESTINATION share/oss-executor/resources
        OPTIONAL)
install(DIRECTORY themes/    DESTINATION share/oss-executor/themes
        OPTIONAL)
install(DIRECTORY scripts/   DESTINATION share/oss-executor/scripts
        OPTIONAL)
