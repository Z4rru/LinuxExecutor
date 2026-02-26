cmake_minimum_required(VERSION 3.20)
project(OSSExecutor VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-O2 -fPIC -Wall -Wextra)

# ── Dependencies ──────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED gtk4)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(LUAJIT REQUIRED luajit)

include(FetchContent)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.13.0
)

FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.2.1
)

FetchContent_MakeAvailable(json spdlog fmt)

# ── Sources ───────────────────────────────────────────────────
file(GLOB_RECURSE SOURCES
    src/*.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    ${GTK4_INCLUDE_DIRS}
    ${LUAJIT_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

target_link_directories(${PROJECT_NAME} PRIVATE
    ${GTK4_LIBRARY_DIRS}
    ${LUAJIT_LIBRARY_DIRS}
    ${CURL_LIBRARY_DIRS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${GTK4_LIBRARIES}
    ${LUAJIT_LIBRARIES}
    ${CURL_LIBRARIES}
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    fmt::fmt
    dl
    pthread
    m
    ssl
    crypto
)

# ── Install ───────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY scripts/ DESTINATION share/oss-executor/scripts)
install(DIRECTORY themes/ DESTINATION share/oss-executor/themes)
install(DIRECTORY resources/ DESTINATION share/oss-executor/resources)
