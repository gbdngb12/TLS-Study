#include <catch2/catch_all.hpp>
#include <iostream>
#include "key_exchange.h"

TEST_CASE("key_exchange") {
    KEY_EXCHANGE::EC_Field f{2, 2, 17};  // y^2 = x^3 + 2x + 2 ( mod 17 )
    KEY_EXCHANGE::EC_Point p{5, 1, f}; //Generate Point
    for(int i = 1; i <= 20; i++) {
        std::cout << i * p << std::endl;
        //i * p;
    }
    auto xA = p * 3;
    auto xB = p * 7;
    auto KA = xB * 3;
    auto KB = xA * 7;
    REQUIRE(KA == KB);
    std::cout << std::endl << xA << xB << KA << KB << std::endl;
}

TEST_CASE("diffie hellman") {
    KEY_EXCHANGE::DiffieHellman Alice, Bob;
    Alice.set_peer_pubkey(Bob.y_);//Bob의 키가 Alice에게 전달
    Bob.set_peer_pubkey(Alice.y_); //Alice의 키가 Bob에게 전달
    REQUIRE(Alice.K_ == Bob.K_);
}