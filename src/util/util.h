#pragma once
#include <gmpxx.h>
#include <sstream>
#include <cassert>
#include <iomanip>
#include <random>

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
    for(unsigned char a : c) {
        ss << std::hex << std::setw(2) << std::setfill('0') << +a;
    }
    return ss.str();
}