project(tls)

add_library(tls der.cpp)

find_library(myjsoncpp jsoncpp REQUIRED)

target_link_libraries(tls
    PUBLIC
        myutil
        ${myjsoncpp}
)
set_target_properties(tls PROPERTIES PUBLIC_HEADER der.h)

# specify the include directory for the library
target_include_directories(tls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})