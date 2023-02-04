#pragma once
#include <gmpxx.h>

#include <utility>

#include "key_exchange.h"
#include "util.h"

namespace AUTH {
class RSA {
   public:
    RSA(int key_size);
    RSA(mpz_class e, mpz_class d, mpz_class K);
    mpz_class sign(mpz_class m);    // 개인키 d 암호화(서명)
    mpz_class decode(mpz_class m);  // 공개키 e 암호화(서명 검증)
    mpz_class encode(mpz_class m);  // 개인키 d 암호화(서명)
    mpz_class K, e;                 // 공개키K, e
   protected:
    mpz_class p /*소수p*/, q /*소수q*/, d /*개인키 d*/, phi /*토티언트 또는 파이*/;
};

class ECDSA : public KEY_EXCHANGE::EC_Point {
   public:
    ECDSA(const EC_Point& G /*Generator Point*/, mpz_class n /*차수*/);
    std::pair<mpz_class /*r*/, mpz_class /*s*/> sign(mpz_class m /*해쉬한 메시지*/, mpz_class d /*비밀키*/) const;
    bool verify(mpz_class m, std::pair<mpz_class /*r*/, mpz_class /*s*/> sig, const EC_Point& Q) const;
    mpz_class mod_inv(const mpz_class &r) const;  // 차수(n)에 대한 나머지 역원을 구하는 함수
   protected:
    mpz_class n_;  // 차수
   private:
    int nBit_;     // 차수의 비트수
    mpz_class d_;  // 비밀키
};
}  // namespace AUTH