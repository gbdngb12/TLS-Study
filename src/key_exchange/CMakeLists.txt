project(key_exchange)

add_library(key_exchange "diffie_hellman.cc" "elliptic_curve.cc") 

target_link_libraries(key_exchange
    PUBLIC
        mpz_util
)
set_target_properties(key_exchange PROPERTIES PUBLIC_HEADER "diffie_hellman.h" PUBLIC_HEADER "elliptic_curve.h")

# specify the include directory for the library
target_include_directories(key_exchange PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})