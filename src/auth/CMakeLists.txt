project(auth)

add_library(auth auth.cpp) 

find_library(myjsoncpp jsoncpp REQUIRED)
# if you are also using the GMPXX library, you will need to link it to the library
#find_package(GMPXX REQUIRED)
find_library(mygmpxx gmpxx REQUIRED)
find_library(mygmp gmp REQUIRED)

if(${mygmp}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no gmp, sad day")
else()
    message(STATUS "gmp found! as ${mygmp}")
endif()

if(${mygmpxx}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
	message(FATAL_ERROR "no gmpxx, sad day")
else()
	message(STATUS "gmpxx found! as ${mygmpxx}")
endif()

target_link_libraries(auth
    PUBLIC
        ${mygmpxx}
        ${mygmp}
        myutil
        key_exchange
        ${myjsoncpp}
)
set_target_properties(auth PROPERTIES PUBLIC_HEADER "auth.h")

# specify the include directory for the library
target_include_directories(auth PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})