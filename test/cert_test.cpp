#include <catch2/catch_all.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include "util.h"
#include "auth.h"
#include "hash.h"

using namespace std;

/*TEST_CASE("base64") {
    std::string s = "aGVsbG8gd29ybGQ=";
    auto v = BASE64::base64_decode(s);
    std::string out;
    for (auto c : v) {
        out += c;
    }
    REQUIRE(out == "hello world");
}*/

std::array<mpz_class, 3> test(std::string s) {
    std::stringstream ss, ss2;
    char c;
    ss << s;
    ss >> setw(2) >> s >> c;
    while(ss >> setw(2) >> s >> c) {
        c = stoi(s, nullptr, 16);
        ss2 << c;
    }
    auto jv = DER::der_to_json(ss2);
    std::cout << jv << std::endl;
    return {UTIL::str_to_mpz(jv[0][0].asString()), UTIL::str_to_mpz(jv[0][1].asString()), UTIL::str_to_mpz(jv[0][2].asString())};
}
TEST_CASE("certificate") {
    std::ifstream f("../../key.pem");
    if (!f) {
        std::cerr << "Failed to open input file" << std::endl;
        //return 1;
    }
    std::string s = DER::get_certificate_core(f);
    auto v = BASE64::base64_decode(s);
    //std::cout << std::internal // fill between the prefix and the number
    //     << std::setfill('0'); // fill with 0s
    //std::cout << "0x";
    //for(const auto &c : v) {
    //    std::cout << std::hex << std::setw(2) << static_cast<int>(c);
    //}
    std::stringstream ss;

    for (uint8_t c : v) {
        ss << c;
    }

    auto jv = DER::der_to_json(ss);
    //std::cout << jv <<std::endl;
    std::string jv_string = jv[0][2].asString();
    auto [K3, E3, D3] = test(jv_string);
    //std::cout << jv[0][2] << std::endl;





    //std::cout << jv[0][0][6][1] << std::endl;
}
/*
TEST_CASE("Check Certificate Chain") {
    std::ifstream f("../../server-cert.pem");
    //첫번째 DER
    string s = DER::get_certificate_core(f);
    auto v = BASE64::base64_decode(s);

    HASH::SHA2 sha;
    int length = v[6] * 256/*v[6] << 8* + v[7] + 4;
    //TBS Certificate를 해쉬한다.
    auto arr = sha.hash(v.begin() + 4, v.begin() + 4 + length);
    cout << "hash" << endl;
    for(const auto& c : arr) {
        cout << setw(2) << setfill('0') << hex<<static_cast<int>(c);
    }
    cout<<endl;

    stringstream ss;
    for(uint8_t c : v) {
        ss << c;
    }
    auto jv = DER::der_to_json(ss);
    auto [K, e, sign] = DER::get_pubkeys(jv);//인증서 1의 서명값을 가져온다.

    //두번째 DER
    s = DER::get_certificate_core(f);
    v = BASE64::base64_decode(s);
    stringstream ss2;
    for(uint8_t c : v) {
        ss2 << c;
    }
    jv = DER::der_to_json(ss2);
    auto [K2, e2, sign2] = DER::get_pubkeys(jv);//인증서 2의 공개키값을 가져온다.

    cout << "sign verify" << endl;
    cout << UTIL::powm(sign, e2, K2);//인증서 1의 서명을 확인한다.

}*/

//374dbaf09c08e4df4c4eeb31ac1799676f39f4bc07993eeb10806bec72efca76
//374dbaf09c08e4df4c4eeb31ac1799676f39f4bc07993eeb10806bec72efca76