cmake_minimum_required(VERSION 3.13.4)
project(catchtest)

add_executable(${PROJECT_NAME} main.cpp)

add_subdirectory("catch2")

target_include_directories(${PROJECT_NAME}
    PUBLIC  "catch2/src"
)

target_link_directories(${PROJECT_NAME}
    PRIVATE "catch2/src"
)

target_link_libraries(${PROJECT_NAME} PRIVATE Catch2::Catch2WithMain)