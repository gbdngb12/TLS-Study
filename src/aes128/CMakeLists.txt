project(aes128)

find_package(OpenMP REQUIRED)
add_library(aes128 aes128.cpp) 

set_target_properties(aes128 PROPERTIES PUBLIC_HEADER "aes128.h")

target_link_libraries(aes128
    PUBLIC
        myutil
)
# specify the include directory for the library
target_include_directories(aes128 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
        OpenMP::OpenMP_CXX
)