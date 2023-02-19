#include <catch2/catch_all.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include "util.h"
#include "auth.h"

TEST_CASE("base64") {
    std::string s = "aGVsbG8gd29ybGQ=";
    auto v = BASE64::base64_decode(s);
    std::string out;
    for (auto c : v) {
        out += c;
    }
    REQUIRE(out == "hello world");
}

TEST_CASE("certificate") {
    std::ifstream f("../../server-cert.pem");
    if (!f) {
        std::cerr << "Failed to open input file" << std::endl;
        //return 1;
    }
    std::string s = DER::get_certificate_core(f);
    auto v = BASE64::base64_decode(s);
    std::cout << std::internal // fill between the prefix and the number
         << std::setfill('0'); // fill with 0s
    std::cout << "0x";
    for(const auto &c : v) {
        std::cout << std::hex << std::setw(2) << static_cast<int>(c);
    }
    //std::stringstream ss;

    //for (uint8_t c : v) {
    //    //std::cout << std::hex << std::setw(4) << 
    //    ss << c;
    //}

    //auto jv = DER::der_to_json(ss);
    //std::cout << jv;
}