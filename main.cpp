#include <catch2/catch_all.hpp>
#include <iostream>
#include "auth.h"
#include <nettle/sha2.h>
//#include "key_exchange.h"
//#include <nettle/curve25519.h>

/*TEST_CASE("RSA_AUTH") {
    AUTH::RSA rsa{256};
    auto a = rsa.encode(mpz_class{"0x23423423"});
    REQUIRE(0x23423423 == rsa.decode(a));

    mpz_class msg = 0x143214324234_mpz;
    auto b = rsa.sign(msg);
    REQUIRE(0x143214324234_mpz == rsa.encode(b));
}*/
TEST_CASE("ECDSA") {
    KEY_EXCHANGE::EC_Field secp256r1{
        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_mpz,//a
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_mpz,//b
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff_mpz//mod p
    };//타원 곡선 정의
    KEY_EXCHANGE::EC_Point G {
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_mpz,//x 
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_mpz,//y
        secp256r1
    };//Generator Point
    //n 차수
    auto n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_mpz;
    mpz_class d = UTIL::random_prime(31);// 비밀키
    auto Q = d * G;//공개키

    AUTH::ECDSA ecdsa{G, n};

    //SHA256 using nettle
    struct sha256_ctx ctx;
    const char message[] = "This is a Test message";
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, strlen(message), (uint8_t *) message);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
    auto z = UTIL::bnd_to_mpz(digest, digest + sizeof(digest) - 1);
    auto sign = ecdsa.sign(z, d);
    REQUIRE(ecdsa.verify(z, sign, Q));
}


/*TEST_CASE("key_exchange") {
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
}*/

/*TEST_CASE("diffie hellman") {
    KEY_EXCHANGE::DiffieHellman Alice, Bob;
    Alice.set_peer_pubkey(Bob.y_);//Bob의 키가 Alice에게 전달
    Bob.set_peer_pubkey(Alice.y_); //Alice의 키가 Bob에게 전달
    REQUIRE(Alice.K_ == Bob.K_);
}*/