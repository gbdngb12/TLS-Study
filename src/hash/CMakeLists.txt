project(hash)

add_library(hash hash.cpp) 

set_target_properties(hash PROPERTIES PUBLIC_HEADER "hash.h")

# specify the include directory for the library
target_include_directories(hash 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)