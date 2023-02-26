project(tcp_ip)

add_library(tcp_ip "tcp_ip.cpp")

set_target_properties(tcp_ip PROPERTIES PUBLIC_HEADER "tcp_ip.h")

# specify the include directory for the library
target_include_directories(tcp_ip 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        tls
)