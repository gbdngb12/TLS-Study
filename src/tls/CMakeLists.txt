project(tls)

find_library(myhog hogweed REQUIRED)

if(${myhog}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no hogweed, sad day")
else()
    message(STATUS "hogweed found! as ${myhog}")
endif()

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
        ${myhog}
)