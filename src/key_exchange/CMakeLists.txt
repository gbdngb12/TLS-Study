project(key_exchange)

add_library(key_exchange key_exchange.cpp) 

# if you are also using the GMPXX library, you will need to link it to the library
#find_package(GMPXX REQUIRED)
find_library(mygmpxx gmpxx REQUIRED)


if(${mygmpxx}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
	message(FATAL_ERROR "no gmpxx, sad day")
else()
	message(STATUS "gmpxx found! as ${mygmpxx}")
endif()

target_link_libraries(key_exchange
    PUBLIC
        ${mygmpxx}
        myutil
)
set_target_properties(key_exchange PROPERTIES PUBLIC_HEADER "key_exchange.h")

# specify the include directory for the library
target_include_directories(key_exchange PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})