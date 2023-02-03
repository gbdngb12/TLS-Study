project(myutil)
add_library(myutil util.cpp) 

# if you are also using the GMPXX library, you will need to link it to the library
#find_package(GMPXX REQUIRED)
find_library(mygmpxx gmpxx REQUIRED)
find_library(mygmp gmp REQUIRED)


if(${mygmpxx}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
	message(FATAL_ERROR "no gmpxx, sad day")
else()
	message(STATUS "gmpxx found! as ${mygmpxx}")
endif()

target_link_libraries(myutil
    PUBLIC
        ${mygmpxx}
        ${mygmp}
)
set_target_properties(myutil PROPERTIES PUBLIC_HEADER util.h)

# specify the include directory for the library
target_include_directories(myutil PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})