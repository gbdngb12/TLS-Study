#pragma once
#include <gmpxx.h>
#include "util.h"
#include <iostream>
#include <cassert>


namespace KEY_EXCHANGE {
class EC_Field {  // y^2 = x^3 + ax + b ( mod mod )
   public:
    EC_Field(mpz_class a, mpz_class b, mpz_class mod);

   protected:
    mpz_class a, b, mod;
    mpz_class mod_inv(const mpz_class &r) const;  // 나머지 역원을 구하는 함수
};

class EC_Point : EC_Field {  // EC_Field 상의 한 좌표
   public:
    EC_Point(mpz_class x, mpz_class y, const EC_Field &f);
    mpz_class x, y;                               // x, y
    EC_Point operator+(const EC_Point &r) const;  // 두 좌표의 합
    EC_Point operator*(mpz_class r) const;        // P * k
    bool operator==(const EC_Point &r) const;
};


// 디피 헬만 클래스
class DiffieHellman {
   private:
    // 256 byte == 2048bit
    mpz_class x_ = UTIL::random_prime(255);  // 비밀키
   public:
    mpz_class K_;  // 공유 세션키 g^{ab} mod p
   //상대방의 공개키 설정 g^b mod p 및 공유 세션키 계산
    mpz_class set_peer_pubkey(mpz_class pub_key);
    mpz_class p_{
        "0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
            D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
            7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
            2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
            984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
            30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
            B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
            0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
            9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
            3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
            886B423861285C97FFFFFFFFFFFFFFFF"};  // 공개키 p
    mpz_class g_ = 2;                            // 공개키 g
    mpz_class y_ = UTIL::powm(g_, x_, p_);       // g^x mod p 공개키
};

}  // namespace KEY_EXCHANGE

std::ostream &operator<<(std::ostream &is, const KEY_EXCHANGE::EC_Point &r);                // 타원곡선 점 출력 함수
KEY_EXCHANGE::EC_Point operator*(const mpz_class &l, const KEY_EXCHANGE::EC_Point &r);  // k * P