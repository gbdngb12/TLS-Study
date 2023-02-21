project(key_exchange)

add_library(key_exchange key_exchange.cpp) 

target_link_libraries(key_exchange
    PUBLIC
        myutil
)
set_target_properties(key_exchange PROPERTIES PUBLIC_HEADER "key_exchange.h")

# specify the include directory for the library
target_include_directories(key_exchange PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})