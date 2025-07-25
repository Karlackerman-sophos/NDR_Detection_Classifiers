cmake_minimum_required(VERSION 3.10) # Minimum CMake version required

# Name your project
project(NDRDetectionFramework CXX)

# Set the C++ standard to C++17 (or newer, if your compiler supports it and you prefer)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories for your project's headers
# Since common.hpp and manager.hpp are in the root, just add current directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add the executable for testing
# The TEST_MAIN_BUILD define should be set to enable the main() function in detection_manager.cpp
# We'll define it here so the test executable is built.
add_definitions(-DTEST_MAIN_BUILD)

# Define your executable
# This creates an executable target named 'detection_manager_test'
# It explicitly lists the source files for the executable.
add_executable(detection_manager_test
    detection_manager.cpp
)

# -----------------------------------------------------------------------------
# Dependency Linking (PLACEHOLDERS - YOU WILL NEED TO ADJUST THESE FOR REAL LIBRARIES)
# -----------------------------------------------------------------------------

# Example for Jansson (if installed via vcpkg, CMake finds it automatically)
# If not using vcpkg, you might need: find_package(Jansson CONFIG REQUIRED)
# Or manually link: target_link_libraries(detection_manager_test PRIVATE jansson)

# Example for libgit2 (if installed via vcpkg, CMake finds it automatically)
# If not using vcpkg, you might need: find_package(LibGit2 CONFIG REQUIRED)
# Or manually link: target_link_libraries(detection_manager_test PRIVATE git2)

# Example for ClickHouse Client Library
# The ClickHouse C++ client typically has its own CMake configuration.
# You'd use find_package or add_subdirectory if it's part of your project.
# For manual linking (if you have pre-compiled binaries):
# target_link_libraries(detection_manager_test PRIVATE <NameOfClickHouseClientLib>)

# If using vcpkg, you would typically run CMake like this (from 'build' directory):
# cmake .. -DCMAKE_BUILD_TYPE=Release -DTEST_MAIN_BUILD=ON -DCMAKE_TOOLCHAIN_FILE=<path_to_vcpkg>/scripts/buildsystems/vcpkg.cmake
# Then vcpkg automatically helps find and link installed libraries.
