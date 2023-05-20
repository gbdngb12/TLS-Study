#pragma once
#include <gmpxx.h>

#include <cassert>
#include <iomanip>
#include <random>
#include <sstream>

namespace tls::mpz_util {

/**
 * @brief n보다 큰 최초의 소수를 리턴한다.
 * 
 * @param n 
 * @return mpz_class 
 */
mpz_class nextprime(mpz_class n);

/**
 * @brief (base^exp) % (mod) 를 계산한다.
 * 
 * @param base 베이스
 * @param exp 지수
 * @param mod 모듈러
 * @return mpz_class 
 */
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);

/**
 * @brief mpz_class에서 big-endian 형식의 배열로 변환한다.
 * 
 * @tparam It 
 * @param n 변환하고자 하는 수
 * @param begin 저장하고자 하는 배열 begin 반복자
 * @param end 저장하고자 하는 배열 end 반복자
 */
template <typename It>
void mpz_to_bnd(mpz_class n, It begin, It end) {
    for (It i = end; i != begin; n /= 0x100) {
        // 연속적인 메모리 구조에 빅엔디안 형식으로 n을 써 넣는다.
        *--i = mpz_class{n % 0x100}.get_ui();
    }
}

/**
 * @brief big-endian 형식의 배열을 mpz_class로 변환한다.
 * 
 * @tparam It 
 * @param begin big-endian 형식의 배열 begin 반복자
 * @param end big-endian 형식의 배열 end 반복자
 * @return mpz_class 결과 숫자
 */
template <typename It>
mpz_class bnd_to_mpz(It begin, It end) {
    std::stringstream ss;
    ss << "0x";
    for (It i = begin; i != end; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
    }
    return mpz_class{ss.str()};
}

/**
 * @brief 원하는 길이의 랜덤 소수를 리턴한다.
 * 
 * @param byte 원하는 길이
 * @return mpz_class 랜덤 소수
 */
mpz_class random_prime(unsigned byte);

// 컨테이너 c의 내용을 16진수 string으로 리턴
/**
 * @brief 컨테이너의 내용을 16진수 string으로 리턴한다.
 * 
 * @tparam C 
 * @param p 해당 컨테이너의 이름 정보
 * @param c 출력하고자 하는 컨테이너
 * @return std::string 
 */
template <class C>
std::string hexprint(const char *p, const C &c) {
    std::stringstream ss;
    ss << p << " : 0x";
    for (unsigned char a : c) {
        ss << std::hex << std::setw(2) << std::setfill('0') << +a;
    }
    return ss.str();
}

}  // namespace tls::util