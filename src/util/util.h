#pragma once
#include <gmpxx.h>

#include <cassert>
#include <iomanip>
#include <random>
#include <sstream>

namespace Util {

// n보다 큰 최초의 소수를 리턴한다.
mpz_class nextprime(mpz_class n);

// base^exp mod mod 를 구한다.
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);

// mpz_class to big endian
template <typename It>
void mpz_to_bnd(mpz_class n, It begin, It end) {
    for (It i = end; i != begin; n /= 0x100) {
        // 연속적인 메모리 구조에 빅엔디안 형식으로 n을 써 넣는다.
        *--i = mpz_class{n % 0x100}.get_ui();
    }
}

// big endian to mpz_class
template <typename It>
mpz_class bnd_to_mpz(It begin, It end) {
    std::stringstream ss;
    ss << "0x";
    for (It i = begin; i != end; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
    }
    return mpz_class{ss.str()};
}

// byte 길이의 소수를 리턴한다.
mpz_class random_prime(unsigned byte);

// 컨테이너 c의 내용을 16진수 string으로 리턴
template <class C>
std::string hexprint(const char *p, const C &c) {
    std::stringstream ss;
    ss << p << " : 0x";
    for (unsigned char a : c) {
        ss << std::hex << std::setw(2) << std::setfill('0') << +a;
    }
    return ss.str();
}

// 디피 헬만 클래스
class DiffieHellman {
   private:
    // 256 byte == 2048bit
    mpz_class x_ = Util::random_prime(255);  // 비밀키
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
    mpz_class y_ = Util::powm(g_, x_, p_);       // g^x mod p 공개키
};

}  // namespace Util