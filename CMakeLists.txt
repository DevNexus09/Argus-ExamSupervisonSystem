cmake_minimum_required(VERSION 3.10)
project(ArgusProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FIX: Help CMake find Homebrew on Apple Silicon (M1/M2/M3)
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
    include_directories(/opt/homebrew/include)
    link_directories(/opt/homebrew/lib)
endif()

# Find System Dependencies
find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)

# Find GLFW
find_package(glfw3 REQUIRED)

# Add Subdirectories
add_subdirectory(Code/Common)
add_subdirectory(Code/Supervisor)
add_subdirectory(Code/Student)