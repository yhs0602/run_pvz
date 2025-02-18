cmake_minimum_required(VERSION 3.11)
project(runner)

# C++11 설정
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LIEF REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# Print capsotne include and library directories
message(STATUS "Capstone include dirs: ${CAPSTONE_INCLUDE_DIRS}")
message(STATUS "Capstone library dirs: ${CAPSTONE_LIBRARY_DIRS}")

add_executable(runner main.cpp)
target_include_directories(runner PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_directories(runner PRIVATE ${CAPSTONE_LIBRARY_DIRS})
target_link_libraries(runner LIEF::LIEF capstone)
