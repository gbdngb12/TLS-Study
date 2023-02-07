add_executable(myTLS aes128.cpp)

target_include_directories(myTLS
    PUBLIC  
        "catch2/src"
)

target_link_directories(myTLS
    PRIVATE
        "catch2/src"
)

target_link_libraries(myTLS
    PRIVATE
        Catch2::Catch2WithMain
        aes128
)