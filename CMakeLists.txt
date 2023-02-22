cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(myTLS)
#Add Compile Option
#add_compile_options(-Dprivate=public)

# Set Test Mode Option
option(TEST_CASE "Build with test case" ON)

if(TEST_CASE)
    # Select Test Target
    option(HASH_TEST "Test HASH" OFF)
    option(AES128_TEST "Test AES128" OFF)
    option(ECDSA_TEST "Test ECDSA" OFF)
    option(KEY_EXCHANGE_TEST "Test Key Exchange" OFF)
    option(CERT_TEST "Test Certificate" OFF)
    option(PRF_TEST "Test PRF" OFF)
    option(TLS_TEST "Test TLS" ON)
endif()

add_subdirectory("catch2")
add_subdirectory("src")

if(TEST_CASE)
    add_subdirectory("test")
endif()
