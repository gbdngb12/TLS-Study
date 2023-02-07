#include <catch2/catch_all.hpp>
#include <iostream>

#include "aes128.h"

TEST_CASE("CBC") {
    AES128::CBC<AES128::AES> cbc;
    unsigned char key[16] = {
        14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14};
    unsigned char iv[16] = {
        1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    cbc.key(key);
    cbc.iv(iv);
    // 32 - 19 + 1
    std::string msg = "Hello this is test";  // 18byte -> need to 14byte padding 13 13 13 13 ... 13
    for (int i = 0; i < 14; i++) {
        msg += 13;
    }
    cbc.encrypt((unsigned char *)msg.data(), 32);
    cbc.decrypt((unsigned char *)msg.data(), 32);
    for (int i = msg.back(); i >= 0; i--) {
        msg.pop_back();  // remove padiing
    }
    REQUIRE(msg == "Hello this is test");
}
