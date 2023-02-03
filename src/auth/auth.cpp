#include "auth.h"
#include <cassert>

AUTH::RSA::RSA(int key_size) {
    //랜덤한 p, q에서 K, phi, e, d를 찾아낸다.
    p = UTIL::random_prime(key_size / 2);
    q = UTIL::random_prime(key_size / 2);
    K = p * q;
    phi = lcm(p-1, q-1);
    for(e = 0x10001; gcd(e, phi) != 1; e = UTIL::nextprime(e));//phi와 서로소인 소수 e선택(공개키)
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());//d는 e와 mod phi에 대한 역수(개인키)
}

AUTH::RSA::RSA(mpz_class e/*공개키*/, mpz_class d/*개인키*/, mpz_class K/*공개키*/) {
    //인증서 혹은 메모리에서 값들을 직접 읽을때
    this->e = e;
    this->d = d;
    this->K = K;
}

mpz_class AUTH::RSA::encode(mpz_class m) {
    //e로 m을 암호화 하는 함수. 서명 검증. K는 m보다 커야한다
    assert(m < K);
    return UTIL::powm(m, e, K);
}

mpz_class AUTH::RSA::decode(mpz_class m) {
    //d로 m을 복호화 하는 함수. 서명. K는 m보다 커야한다.
    assert(m < K);
    return UTIL::powm(m, d, K);
}

mpz_class AUTH::RSA::sign(mpz_class m) {
    return decode(m);
}