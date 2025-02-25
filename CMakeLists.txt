cmake_minimum_required(VERSION 3.15)
project(runner)

# C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

# Print capsotne include and library directories
message(STATUS "Capstone include dirs: ${CAPSTONE_INCLUDE_DIRS}")
message(STATUS "Capstone library dirs: ${CAPSTONE_LIBRARY_DIRS}")

add_executable(
    runner
    main.cpp
    virtual_cpu.cpp
    virtual_cpu_stack.cpp
    virtual_cpu_memory.cpp
    virtual_cpu_mov.cpp
    virtual_cpu_arith.cpp
)
target_include_directories(runner PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_directories(runner PRIVATE ${CAPSTONE_LIBRARY_DIRS})
target_link_libraries(runner LIEF::LIEF capstone)
