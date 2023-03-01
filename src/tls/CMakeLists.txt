project(tls)

add_library(tls "tls.cpp" "tls13.cpp")

set_target_properties(tls PROPERTIES PUBLIC_HEADER "tls.h;tls13.h")

# specify the include directory for the library
target_include_directories(tls 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        myutil
        hash
        auth
        aes128
)