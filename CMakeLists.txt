cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(catchtest)

add_subdirectory("catch2")
add_subdirectory("src")

add_executable(${PROJECT_NAME} main.cpp)

find_library(mynettle nettle REQUIRED)

if(${nettle}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no nettle, sad day")
else()
    message(STATUS "nettle found! as ${nettle}")
endif()

target_include_directories(${PROJECT_NAME}
    PUBLIC  
        "catch2/src"
)

target_link_directories(${PROJECT_NAME}
    PRIVATE
        "catch2/src"
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Catch2::Catch2WithMain
        myutil
        auth
    PUBLIC
        ${nettle}
)