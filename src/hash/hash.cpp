#include "hash.h"

template class HASH::HMAC<HASH::SHA1>;
template class HASH::HKDF<HASH::SHA2>;

void HASH::SHA1::preprocess(std::vector<unsigned char> &v) {
    size_t sz = v.size() * 8;  // 메시지길이 비트수
    v.push_back(0x80);
    for (int i = 0; i < 8; i++) {  // size를 적기 위한 공간
        v.push_back(0);
    }
    while (v.size() % 64) {  // 64바이트의 배수가 안된다면 0을 삽입하여 64바이트의 배수로 만듦
        v.push_back(0);
    }
    // big endian 방식으로 메시지길이의 비트수를 저장한다.
    for (auto it = v.rbegin(); sz; sz /= 0x100) {
        *it++ = sz % 0x100;
    }
}

HASH::SHA1::SHA1() {
    int k = 0x12345678;
    if (htonl(k) == k) {  // 만약 네트워크 방식(빅엔디안)으로 변경 했는데도 값이 똑같다면 현재 컴퓨터는 빅엔디안 컴퓨터
        big_endian_ = true;
    }
}

uint32_t HASH::SHA1::left_rotate(uint32_t a, int bits) {  // 좌측 순환 쉬프트
    return a << bits | a >> (32 - bits);
}

void HASH::SHA1::process_chunk(unsigned char *p) {
    // w 생성(64바이트에서 8바이트 배열로 확장)
    memcpy(w, p, block_size);
    if (!big_endian_) {  // little endian이라면 빅엔디안 형식으로 저장
        for (int i = 0; i < 16; i++) {
            w[i] = htonl(w[i]);
        }
    }
    // w0~w15는 그대로 저장, w16~w79는 공식에 따라 저장
    for (int i = 16; i < 80; i++) {
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    // 블록의 라운드 계산
    // 초기값 설정
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f /*기약함수*/, tmp /*a값을 저장하기 위한 임시 변수*/;
    const uint32_t k[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};  // k값은 라운드 별로 사용하는 상수
    for (int i = 0; i < 80; i++) {
        switch (i / 20) {  // 기약함수 설정
            case 0:
                f = (b & c) | ((~b) & d);
                break;
            case 1:
                f = b ^ c ^ d;
                break;
            case 2:
                f = (b & c) | (b & d) | (c & d);
                break;
            case 3:
                f = b ^ c ^ d;
                break;
        }
        tmp = left_rotate(a, 5) + f + e + k[i / 20] + w[i];  // a
        e = d /*e*/;
        d = c;                  /*d*/
        c = left_rotate(b, 30); /*c*/
        b = a;                  /*b*/
        a = tmp;
    }
    // h값 업데이트
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

HASH::SHA2::SHA2() {
    sha256_init(&sha_);
}
