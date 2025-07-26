# Set the minimum required version of CMake and define the C++ standard.
cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the project name and language.
project(detection_manager_test CXX)

# This is the modern vcpkg integration that should handle everything automatically,
# but is not working correctly in your environment. We leave it here.
find_package(Jansson REQUIRED)
find_package(libgit2 REQUIRED)

# Add the executable target and its source files.
add_executable(${PROJECT_NAME}
    detection_manager.cpp
)

# --- Manual Workaround Starts Here ---

# 1. Manually tell CMake where to find header files (.h) for the compiler.
target_include_directories(${PROJECT_NAME} PRIVATE
    "C:/Dev/vcpkg/installed/x64-windows/include"
)

# 2. Manually tell CMake where to find library files (.lib) for the linker.
target_link_directories(${PROJECT_NAME} PRIVATE
    "C:/Dev/vcpkg/installed/x64-windows/lib"
)

# --- Manual Workaround Ends Here ---


# Link the libraries by name. The linker will now find them
# because of the target_link_directories command above.
target_link_libraries(${PROJECT_NAME} PRIVATE
    jansson
    git2
)

# Defines the TEST_MAIN_BUILD macro so main() is included.
target_compile_definitions(${PROJECT_NAME} PRIVATE TEST_MAIN_BUILD)