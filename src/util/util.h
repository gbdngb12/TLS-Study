#pragma once
#include <gmpxx.h>
#include <cassert>
#include <iomanip>
#include <random>
#include <sstream>

namespace UTIL {

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

/*!
 * @brief       DER인증서에 저장된 문자열을 mpz_class 숫자로 변환 하는 함수
 * @param       s 문자열 숫자
 * @result      mpz_class 숫자
 */
mpz_class str_to_mpz(std::string s);
}  // namespace Util

namespace BASE64 {
    /*!
 * @brief       6bits값을 base64 char로 치환
 * @param       n
 * @result      base64로 인코딩된 char
 */
char bits_to_char(unsigned char n);

/*!
 * @brief       base64 char값을 6bits로 복구
 * @param       c   
 * @result      base64 디코딩된 char
 */
unsigned char char_to_bits(char c);

/*!
 * @brief       base64 인코딩
 * @param       v 인코딩할 unsigned char vector
 * @result      base64 인코딩한 string
 */
std::string base64_encode(std::vector<unsigned char> v);

/*!
 * @brief       base64 디코딩
 * @param       s 디코딩할 string
 * @result      base64 디코딩한 unsigned char vector
 */
std::vector<unsigned char> base64_decode(std::string s);


}