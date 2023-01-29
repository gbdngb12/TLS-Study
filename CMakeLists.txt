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
#find_package(Catch2 REQUIRED)
# These tests can use the Catch2-provided main
#add_executable(tests test.cpp)
#target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)

# These tests need their own main
#add_executable(custom-main-tests test.cpp) #test-main.cpp)
#target_link_libraries(custom-main-tests PRIVATE Catch2::Catch2)