cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(myTLS)

# Set Test Mode Option
option(TEST_CASE "Build with test case" ON)

if(TEST_CASE)
    # Select Test Target
    option(AES128_TEST "Test AES128" ON)
    option(ECDSA_TEST "Test ECDSA" OFF)
    option(KEY_EXCHANGE_TEST "Test Key Exchange" OFF)
endif()

add_subdirectory("catch2")
add_subdirectory("src")

if(TEST_CASE)
    add_subdirectory("test")
endif()