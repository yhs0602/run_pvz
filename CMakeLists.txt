cmake_minimum_required(VERSION 3.15)
project(runner)

# C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PVZ_CPU_BACKEND "unicorn" CACHE STRING "CPU backend (unicorn|fexcore)")
set_property(CACHE PVZ_CPU_BACKEND PROPERTY STRINGS unicorn fexcore)
if(PVZ_CPU_BACKEND STREQUAL "unicorn")
    add_compile_definitions(PVZ_CPU_BACKEND_UNICORN=1)
elseif(PVZ_CPU_BACKEND STREQUAL "fexcore")
    add_compile_definitions(PVZ_CPU_BACKEND_FEXCORE=1)
else()
    message(FATAL_ERROR "Unsupported PVZ_CPU_BACKEND='${PVZ_CPU_BACKEND}'. Use 'unicorn' or 'fexcore'.")
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug/Release)" FORCE)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-g) # 디버그 심볼 추가
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/Zi /Od) # MSVC 디버그 심볼
    add_link_options(/DEBUG) # MSVC 디버그 링커 옵션
endif()

find_package(LIEF REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
pkg_check_modules(UNICORN REQUIRED unicorn)
pkg_check_modules(SDL2 REQUIRED sdl2)

# Print include and library directories
message(STATUS "Capstone include dirs: ${CAPSTONE_INCLUDE_DIRS}")
message(STATUS "Capstone library dirs: ${CAPSTONE_LIBRARY_DIRS}")
message(STATUS "Unicorn include dirs: ${UNICORN_INCLUDE_DIRS}")
message(STATUS "Unicorn library dirs: ${UNICORN_LIBRARY_DIRS}")
message(STATUS "SDL2 include dirs: ${SDL2_INCLUDE_DIRS}")
message(STATUS "SDL2 library dirs: ${SDL2_LIBRARY_DIRS}")

add_executable(
    runner
    backend/unicorn_backend.cpp
    backend/fexcore_backend.cpp
    main.cpp
    windows_env.cpp
    api_handler.cpp
    pe_loader.cpp
)
target_include_directories(runner PRIVATE ${CAPSTONE_INCLUDE_DIRS} ${UNICORN_INCLUDE_DIRS} ${SDL2_INCLUDE_DIRS})
target_link_directories(runner PRIVATE ${CAPSTONE_LIBRARY_DIRS} ${UNICORN_LIBRARY_DIRS} ${SDL2_LIBRARY_DIRS})
target_link_libraries(runner LIEF::LIEF capstone unicorn ${SDL2_LIBRARIES})

add_library(
    pvz_fexcore_bridge
    SHARED
    bridge/pvz_fexcore_bridge.cpp
)
target_include_directories(pvz_fexcore_bridge PRIVATE ${UNICORN_INCLUDE_DIRS})
target_link_directories(pvz_fexcore_bridge PRIVATE ${UNICORN_LIBRARY_DIRS})
target_link_libraries(pvz_fexcore_bridge unicorn)
set_target_properties(pvz_fexcore_bridge PROPERTIES OUTPUT_NAME "pvz_fexcore_bridge")
