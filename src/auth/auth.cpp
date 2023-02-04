#include "auth.h"

#include <cassert>

AUTH::RSA::RSA(int key_size) {
    // 랜덤한 p, q에서 K, phi, e, d를 찾아낸다.
    p = UTIL::random_prime(key_size / 2);
    q = UTIL::random_prime(key_size / 2);
    K = p * q;
    phi = lcm(p - 1, q - 1);
    for (e = 0x10001; gcd(e, phi) != 1; e = UTIL::nextprime(e))
        ;                                                       // phi와 서로소인 소수 e선택(공개키)
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());  // d는 e와 mod phi에 대한 역수(개인키)
}

AUTH::RSA::RSA(mpz_class e /*공개키*/, mpz_class d /*개인키*/, mpz_class K /*공개키*/) {
    // 인증서 혹은 메모리에서 값들을 직접 읽을때
    this->e = e;
    this->d = d;
    this->K = K;
}

mpz_class AUTH::RSA::encode(mpz_class m) {
    // e로 m을 암호화 하는 함수. 서명 검증. K는 m보다 커야한다
    assert(m < K);
    return UTIL::powm(m, e, K);
}

mpz_class AUTH::RSA::decode(mpz_class m) {
    // d로 m을 복호화 하는 함수. 서명. K는 m보다 커야한다.
    assert(m < K);
    return UTIL::powm(m, d, K);
}

mpz_class AUTH::RSA::sign(mpz_class m) {
    return decode(m);
}

AUTH::ECDSA::ECDSA(const EC_Point &g /*generator Point*/, mpz_class n) : EC_Point{g} {
    this->n_ = n;
    this->nBit_ = mpz_sizeinbase(n.get_mpz_t(), 2);  // 2진수로 몇자리인지 리턴함
}

mpz_class AUTH::ECDSA::mod_inv(const mpz_class &z) const {  // mod n에대한 나머지 역원을 구함
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), this->n_.get_mpz_t());
    return r;
}

std::pair<mpz_class, mpz_class> AUTH::ECDSA::sign(mpz_class m /*해쉬한 메시지*/, mpz_class d /*비밀키*/) const {
    int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);   // 메시지의 비트수를 구한다.
    mpz_class z = m >> std::max(mBit - nBit_, 0);  // 해쉬된 값이 너무 클 경우는 뒤쪽의 비트를 버린다.

    // ECDSA 서명 생성 알고리즘
    mpz_class k, s, r;
    EC_Point Q = *this;  // 공개키
    do {                 // s 값 확인 루프
        do {             // r값 확인 루프
            k = UTIL::random_prime(31);
            Q = k * *this;  // Q = kG
            r = Q.x % this->n_;
        } while (r == 0);
        s = (this->mod_inv(k) * (z + r * d)) % this->n_;
    } while (s == 0);
    return {r, s};
}

bool AUTH::ECDSA::verify(mpz_class m /*서명 메시지의 해시*/, std::pair<mpz_class, mpz_class> sig
                         /*서명 쌍*/,
                         const EC_Point &Q /*공개키*/) const {
    // ECDSA 서명 검증 알고리즘
    auto [r, s] = sig;
    for(auto a : {r, s}) {
        if(a < 1 || a >= this->n_) {
        //서명 쌍은 반드시 0이면안되고, mod n을 했으므로 n보다 크거나 같으면 안된다.
            return false;
        }
    }

    int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);//서명 메시지의 해시비트
    mpz_class z = m >> std::max(mBit - nBit_, 0);//해시값이 크면 끝값을 버린다.
    mpz_class u = (z * mod_inv(s)) % this->n_;
    mpz_class v = (r * mod_inv(s)) % this->n_;
    EC_Point P = u * *this + v * Q; //P = uG + vQ
    if(P.y == this->mod) return false; //if P is O
    if((P.x - r) % this->n_ == 0) return true;// (x ≡ r mod n)
    else return false;
}