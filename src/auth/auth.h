#pragma once
#include <gmpxx.h>

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
}  // namespace AUTH