#include "auth.h"

#include <cassert>
using namespace std;

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

AUTH::ECDSA::ECDSA(const EC_Point& g /*generator Point*/, mpz_class n) : EC_Point{g} {
    this->n_ = n;
    this->nBit_ = mpz_sizeinbase(n.get_mpz_t(), 2);  // 2진수로 몇자리인지 리턴함
}

mpz_class AUTH::ECDSA::mod_inv(const mpz_class& z) const {  // mod n에대한 나머지 역원을 구함
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
                         const EC_Point& Q /*공개키*/) const {
    // ECDSA 서명 검증 알고리즘
    auto [r, s] = sig;
    for (auto a : {r, s}) {
        if (a < 1 || a >= this->n_) {
            // 서명 쌍은 반드시 0이면안되고, mod n을 했으므로 n보다 크거나 같으면 안된다.
            return false;
        }
    }

    int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);   // 서명 메시지의 해시비트
    mpz_class z = m >> std::max(mBit - nBit_, 0);  // 해시값이 크면 끝값을 버린다.
    mpz_class u = (z * mod_inv(s)) % this->n_;
    mpz_class v = (r * mod_inv(s)) % this->n_;
    EC_Point P = u * *this + v * Q;      // P = uG + vQ
    if (P.y == this->mod) return false;  // if P is O
    if ((P.x - r) % this->n_ == 0)
        return true;  // (x ≡ r mod n)
    else
        return false;
}

DER::Type DER::read_type(unsigned char c) {
    DER::Type type;
    type.cls = static_cast<DER::Class>((c & 0b11000000) >> 6);
    type.pc = static_cast<DER::PC>((c & 0b00100000) >> 5);
    type.tag = static_cast<DER::Tag>(c & 0b00011111);
    return type;
}

int DER::read_length(std::istream& is) {
    unsigned char c;
    // 모든 공백을 skip하지 않고 c에 삽입
    if (!(is >> noskipws >> c)) throw "reached eof in read_length";
    if (c & 0b10000000) {  // 여러 바이트로 길이를 표현 하는 경우
        vector<unsigned char> v;
        for (int i = 0, j = c & 0b01111111 /*멀티바이트 최대값*/; i < j; i++) {
            is >> c;
            v.push_back(c);
        }
        return UTIL::bnd_to_mpz(v.begin(), v.end()).get_si();
    } else {  // 한바이트로 길이를 표현 하는 경우
        return c;
    }
}

vector<unsigned char> DER::read_value(istream& is, int len) {
    unsigned char c;
    vector<unsigned char> v;
    // contents length만큼 unsigned char 값으로 vector를 만든다.
    for (int i = 0; i < len; i++) {
        if (!(is >> noskipws >> c)) throw "reached eof in read_value";
        v.push_back(c);
    }
    return v;
}

Json::Value DER::type_change(DER::Tag tag, vector<unsigned char> v) {
    switch (tag) {
        case DER::Tag::EOC:
            return "eoc";
        case DER::Tag::BOOLEAN:
            return v[0] ? true : false;
        case DER::Tag::INTEGER:  // return (int)bnd2mpz(v.begin(), v.end()).get_si();
        case DER::Tag::BIT_STRING:
        case DER::Tag::OCTET_STRING:
        case DER::Tag::NUMERIC_STRING:
        case DER::Tag::OBJECT_IDENTIFIER:
        case DER::Tag::OBJECT_DESCRIPTOR: {  // 두 바이트씩 16진수로 해석 마지막에는 ':'
            stringstream ss;
            for (auto a : v) ss << hex << setw(2) << setfill('0') << +a << ':';
            return ss.str();
        }
        case DER::Tag::NULL_TYPE:
            return "null";
        case DER::Tag::EXTERNAL:
        case DER::Tag::REAL:
            return *(float*)v.data();
        case DER::Tag::ENUMERATED:
        case DER::Tag::EMBEDDED_PDV:
        case DER::Tag::RELATIVE_OID:

        default: {  // strings 문자열로 해석
            stringstream ss;
            for (auto a : v) ss << a;
            return ss.str();
        }
    }
}

Json::Value DER::read_constructed(std::istream& is, int length) {
    // 복합적인 DER Contents중 한 부분을 읽는 함수
    Json::Value jv;
    int start_pos = is.tellg();
    unsigned char c;
    for (int i = 0, l; ((int)is.tellg() - start_pos < length) /*현재위치가 length보다 작아야하고*/ && (is >> noskipws >> c) /*null이면 안된다.*/; i++) {
        auto type = DER::read_type(c);
        l = DER::read_length(is);
        jv[i] = type.pc == DER::PC::PRIMITIVE ?
                                              /*단일 데이터라면*/ DER::type_change(type.tag, DER::read_value(is, l))
                                              : /*복합 데이터라면 재귀 호출*/ DER::read_constructed(is, l);
    }
    return jv;
}

Json::Value DER::der_to_json(std::istream& is) {
    Json::Value jv;
    unsigned char c;
    for (int i = 0, l; is >> noskipws >> c; i++) {
        auto type = DER::read_type(c);
        l = DER::read_length(is);
        jv[i] = type.pc == DER::PC::PRIMITIVE ?
                                              /*단일 데이터인 경우*/ DER::type_change(type.tag, DER::read_value(is, l))
                                              : DER::read_constructed(is, l);
    }
    return jv;
}

std::string DER::get_certificate_core(std::istream& is) {
    string s, r;
    while (s != "-----BEGIN")
        if (!(is >> s)) return r;
    getline(is, s);                                  // 여기서 CERTIFICATE-----를 읽는다.
    for (is >> s; s != "-----END"; is >> s) r += s;  // base64인코딩된 값을 읽는다.
    return r;
}

std::array<mpz_class, 2> DER::process_bitstring(std::string s) {
    stringstream ss, ss2;
    char c;
    ss << s;
    ss >> setw(2) >> s >> c;  // c는 16진수 ':'을 받아들임
    while (ss >> setw(2) >> s >> c /*':'를 버림*/) {
        c = stoi(s, nullptr, 16);  // 숫자 문자열을 16진수로 변환해 c에 저장
        ss2 << c;
    }
    // ss2 : 0x00 30 82 01 0a 02 82 01 01 00 c0 95 08 e1 57 41 f2 71 6d b7 d2 45 41 27 01 65 c6 45 ....
    auto jv = DER::der_to_json(ss2);
    return { UTIL::str_to_mpz(jv[0][0].asString())/*K*/, UTIL::str_to_mpz(jv[0][1].asString()) /*e*/ };
}

std::array<mpz_class, 3> DER::get_pubkeys(const Json::Value& jv) {
    auto [a, b] = DER::process_bitstring(jv[0][0][6][1].asString());
    auto c = UTIL::str_to_mpz(jv[0][2].asString());  // Signature
    return {a, b, c};                                // K, e, Sign
}