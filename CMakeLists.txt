cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 20)

project(tls)

# Set Test Mode Option
option(TEST_CASE "Build with test case" ON)

add_subdirectory("src")

if(TEST_CASE)
    add_subdirectory("test")
endif()