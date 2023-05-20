project(test)

find_package(Catch2 3 REQUIRED)
# These tests can use the Catch2-provided main
add_executable(${PROJECT_NAME} "key_exchange.cc")
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        Catch2::Catch2WithMain
        key_exchange
)