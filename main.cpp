#include <catch2/catch_all.hpp>
#include <iostream>

#include "ecdhe.h"
// #include "util.h"

TEST_CASE("key_exchange") {
    EllipticCurveDHE::EC_Field f{2, 2, 17};  // y^2 = x^3 + 2x + 2 ( mod 17 )
    EllipticCurveDHE::EC_Point p{5, 1, f}; //Generate Point

    for(int i = 1; i <= 20; i++) {
        std::cout << i * p << std::endl;
    }
    auto xA = p * 3;
    auto xB = p * 7;
    auto KA = xB * 3;
    auto KB = xA * 7;
    REQUIRE(KA == KB);
    std::cout << std::endl << xA << xB << KA << KB << std::endl;
}