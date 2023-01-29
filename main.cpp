#include <catch2/catch_all.hpp>

#include "util.h"

TEST_CASE("diffie hellman") {
    Util::DiffieHellman Alice, Bob;
    Alice.set_peer_pubkey(Bob.y_);//Bob의 키가 Alice에게 전달
    Bob.set_peer_pubkey(Alice.y_); //Alice의 키가 Bob에게 전달
    REQUIRE(Alice.K_ == Bob.K_);
}