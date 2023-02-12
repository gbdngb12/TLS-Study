project(hash)

add_library(hash hash.cpp)
find_library(mynettle nettle REQUIRED)

if(${mynettle}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no nettle, sad day")
else()
    message(STATUS "nettle found! as ${mynettle}")
endif()

set_target_properties(hash PROPERTIES PUBLIC_HEADER "hash.h")

# specify the include directory for the library
target_include_directories(hash 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        ${mynettle}
)