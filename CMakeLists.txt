cmake_minimum_required(VERSION 3.13.4)

# Set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(catchtest)

add_subdirectory("catch2")
add_subdirectory("src/util")

add_executable(${PROJECT_NAME} main.cpp)


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
)