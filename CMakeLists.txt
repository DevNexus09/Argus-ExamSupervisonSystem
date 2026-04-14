cmake_minimum_required(VERSION 3.10)
project(ArgusProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FIX: Help CMake find Homebrew on Apple Silicon & Silence OpenGL Warnings
if(APPLE)
    add_compile_definitions(GL_SILENCE_DEPRECATION)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
    include_directories(/opt/homebrew/include)
    link_directories(/opt/homebrew/lib)
endif()

# Find System Dependencies
find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)

# FIX: Bulletproof GLFW Finder for both Mac AND Linux
find_package(glfw3 QUIET)
if(NOT glfw3_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
else()
    set(GLFW_LIBRARIES glfw)
endif()

# Add Subdirectories
add_subdirectory(Code/Common)
add_subdirectory(Code/Supervisor)
add_subdirectory(Code/Student)