#include <catch2/catch_all.hpp>
#include <iostream>
#include "auth.h"
#include <nettle/sha2.h>

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