#include <catch2/catch_all.hpp>
#include <iostream>
//#include "diffie_hellman.h"
#include "elliptic_curve.h"
#include "mpz_util.h"
using namespace tls::key_exchange;
using namespace tls::mpz_util;

/*TEST_CASE("Diffie Hellman") {
    DiffieHellman Alice, Bob;
    Alice.set_peer_pubkey(Bob.get_public_key());
    Bob.set_peer_pubkey(Alice.get_public_key());
    std::cout << Alice.get_shared_key() << std::endl;
    std::cout << Bob.get_shared_key() << std::endl;
    REQUIRE(Alice.get_shared_key() == Bob.get_shared_key());
}*/

TEST_CASE("mpz") {
    uint8_t arr[8];
    mpz_class a{"0x1234567890abcdef"};
    mpz_to_bnd(a, arr, arr + 8);
    mpz_class b{bnd_to_mpz(arr, arr + 8)};
    REQUIRE(a == b);
}

TEST_CASE("secp256k1") {

}