if(AES128_TEST)
    find_library(mynettle nettle REQUIRED)
    if(${mynettle}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
        message(FATAL_ERROR "no nettle, sad day")
    else()
        message(STATUS "nettle found! as ${mynettle}")
    endif()
    list(APPEND EXTRA_LIBS ${mynettle})
    list(APPEND MY_TEST_LIST "aes128_test.cpp")
    list(APPEND EXTRA_LIBS aes128)
endif()

if(ECDSA_TEST)
    list(APPEND MY_TEST_LIST "ecdsa_test.cpp")

    find_library(mynettle nettle REQUIRED)
    if(${mynettle}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
        message(FATAL_ERROR "no nettle, sad day")
    else()
        message(STATUS "nettle found! as ${mynettle}")
    endif()

    list(APPEND EXTRA_LIBS auth)
    list(APPEND EXTRA_LIBS ${mynettle})
endif()

if(KEY_EXCHANGE_TEST)
    list(APPEND MY_TEST_LIST "key_exchange_test.cpp")
    list(APPEND EXTRA_LIBS key_exchange)
endif()


add_executable(${PROJECT_NAME} ${MY_TEST_LIST})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "catch2/src"
)

target_link_directories(${PROJECT_NAME}
    PRIVATE
        "catch2/src"
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Catch2::Catch2WithMain
        ${EXTRA_LIBS}
)