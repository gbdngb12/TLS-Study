#include "util.h"

// n보다 큰 최초의 소수를 리턴한다.
mpz_class Util::nextprime(mpz_class n) {
    mpz_class r;
    mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
    return r;
}

// base^exp mod mod 를 구한다.
mpz_class Util::powm(mpz_class base, mpz_class exp, mpz_class mod) {
    mpz_class r;
    assert(mod);
    mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return r;
}

// byte 길이의 소수를 리턴한다.
mpz_class Util::random_prime(unsigned byte) {
    unsigned char arr[byte];
    std::uniform_int_distribution<int> di(0, 0xff);
    // 0 ~ 255의 임의의 정수를 균등한 확률로 생성
    std::random_device rd;
    // arr에 랜덤한 값을 가지는 배열 저장
    for (int i = 0; i < byte; i++) {
        arr[i] = di(rd);
    }
    // z에 랜덤한 수의 바로 다음에 오는 소수 설정
    auto z = Util::nextprime(Util::bnd_to_mpz(arr, arr + byte));
    for (int i = 0; i < byte; i++) {
        arr[i] = 0xff;
    }
    // 만약 바로 다음오는 소수가 byte로 표현 가능한 최대치보다 클경우
    // 다시 생성
    if (z > Util::bnd_to_mpz(arr, arr + byte)) {
        return Util::random_prime(byte);
    } else {  // 만약 범위안에 존재할 경우 그값 리턴
        return z;
    }
}

mpz_class Util::DiffieHellman::set_peer_pubkey(mpz_class pub_key) {
    K_ = Util::powm(pub_key, x_, p_);
    return K_;
}