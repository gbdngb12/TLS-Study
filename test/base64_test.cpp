#include <catch2/catch_all.hpp>
#include <iostream>
#include <string>

#include "der.h"

TEST_CASE("base64") {
    std::string s = "aGVsbG8gd29ybGQ=";
    auto v = DER::base64_decode(s);
    std::string out;
    for (auto c : v) {
        out += c;
    }
    REQUIRE(out == "hello world");
}