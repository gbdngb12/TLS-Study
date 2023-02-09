#include "aes128.h"

template class AES128::CBC<AES128::AES>;
template class AES128::GCM<AES128::AES>;
template class AES128::CipherMode<AES128::AES>;

void AES128::AES::shift_row(unsigned char *p) const {
    unsigned char tmp, tmp2;
    tmp = p[1];
    p[1] = p[5];
    p[5] = p[9];
    p[9] = p[13];
    p[13] = tmp;
    tmp = p[2];
    tmp2 = p[6];
    p[2] = p[10];
    p[6] = p[14];
    p[10] = tmp;
    p[14] = tmp2;
    tmp = p[3];
    p[3] = p[15];
    p[15] = p[11];
    p[11] = p[7];
    p[7] = tmp;
}

void AES128::AES::inv_shift_row(unsigned char *p) const {
    unsigned char tmp, tmp2;
    tmp = p[13];
    p[13] = p[9];
    p[9] = p[5];
    p[5] = p[1];
    p[1] = tmp;
    tmp = p[10];
    tmp2 = p[14];
    p[14] = p[6];
    p[10] = p[2];
    p[6] = tmp2;
    p[2] = tmp;
    tmp = p[7];
    p[7] = p[11];
    p[11] = p[15];
    p[15] = p[3];
    p[3] = tmp;
}

void AES128::AES::substitue(unsigned char *p) const {
    for (int i = 0; i < 16; i++) p[i] = sbox[p[i]];
}

void AES128::AES::inv_substitue(unsigned char *p) const {
    for (int i = 0; i < 16; i++) p[i] = inv_sbox[p[i]];
}

unsigned char AES128::AES::doub(unsigned char c) const {  // ⊗2연산 구현
    bool left_most_bit = c & (1 << 7);
    c <<= 1;
    if (left_most_bit) c ^= 0x1b;
    return c;
}

void AES128::AES::mix_column(unsigned char *p) const {
    static const unsigned char mix[4][4] = {
        {2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
    unsigned char c[4], d, result[16];
    for (int y = 0; y < 4; y++)
      for (int x = 0; x < 4; x++) {    // 열
        for (int i = 0; i < 4; i++) {  // 행렬 곱셈시 열 증가
          d = p[4 * x + i];            // 원본 문자열
          // 배열의 값과 정의된 행렬간에 갈루아 필드 곱하기 수행
          switch (mix[y][i] /*정의된 행렬*/) {
            case 1:
              c[i] = d;
              break;
            case 2:
              c[i] = d << 1;
              break;
            case 3:
              c[i] = d << 1 ^ d;
              break;
          }
          // 최상위 비트값에 따른 처리: 최상위 비트가 1이고 ⊗ 1이 아니면
          if ((d & (1 << 7)) && (mix[y][i] != 1)) {
            c[i] ^= 0x1b;
          }
        }
        // 원소 하나 끝났으면 모두 xor
        result[4 * x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
      }
    memcpy(p, result, 16);
}

void AES128::AES::inv_mix_column(unsigned char *p) const {
    static const unsigned char inv_mix[4][4] = {
        {14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}};
    unsigned char c[4], d, result[16];
    for (int y = 0; y < 4; y++)
        for (int x = 0; x < 4; x++) {      // 열
            for (int i = 0; i < 4; i++) {  // 행렬 곱셈시 열 증가
                d = p[4 * x + i];          // 원본 문자열
                // 배열의 값과 정의된 행렬간에 갈루아 필드 곱하기 수행
                switch (inv_mix[y][i] /*정의된 행렬*/) {
                    case 9:
                        c[i] = doub(doub(doub(d))) ^ d;
                        break;
                    case 11:
                        c[i] = doub(doub(doub(d)) ^ d) ^ d;
                        break;
                    case 13:
                        c[i] = doub(doub(doub(d) ^ d)) ^ d;
                        break;
                    case 14:
                        c[i] = doub(doub(doub(d) ^ d) ^ d);
                        break;
                }
            }
            // 원소 하나 끝났으면 모두 xor
            result[4 * x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
        }
    memcpy(p, result, 16);
}
/*
9⊗a = 2⊗(2⊗(2⊗a))⊕a
11⊗a = 2⊗((2⊗(2⊗a))⊕a)⊕a
13⊗a = 2⊗(2⊗((2⊗a)⊕a))⊕a
14⊗a = 2⊗(2⊗((2⊗a)+a)+a)

*/
void AES128::AES::key(const unsigned char *pkey) {
    memcpy(schedule_[0], pkey, 16);
    unsigned char *p = &schedule_[1][0];  // round 1
    for (int i = 1; i < ROUND; i++) {
        // 1. 앞 라운드의 마지막 4바이트를 왼쪽으로 rotate
        for (int j = 0; j < 3; j++) {
            *(p + j) = *(p + j - 3);
        }
        *(p + 3) = *(p - 4);
        // 2. sbox를 이용해 치환한다.
        for (int j = 0; j < 4; j++) {
            *(p + j) = sbox[*(p + j)];
        }
        for (int j = 0; j < 4; j++, p++) {  // N key size in word
            *p ^= rcon[4 * i / N - 1][j];   // 3. 그 라운드의 상수값과 xor
            *p ^= *(p - 4 * N);             // 4. 앞 라운드의 첫 4바이트와 xor 한다.
        }
        // 5. 나머지 12바이트 생성
        // 앞 라운드의 바이트와 자신의 4바이트 앞의 것을 xor한다.
        for (int j = 0; j < 12; j++, p++) {
            *p = *(p - 4 * N) /*앞 라운드의 바이트*/ ^ *(p - 4) /*자신의 4바이트 앞의 값*/;
        }
    }
}

// 확장된 키와 메시지를 라운드에 맞춰 xor한다.
// xor연산 이므로 역연산, 연산은 동일하다.
void AES128::AES::add_round_key(unsigned char *msg, int round) const {
    for (int i = 0; i < 16; i++) {
        msg[i] ^= schedule_[round][i];
    }
}

// AES 암호화 함수
void AES128::AES::encrypt(unsigned char *m) const {
    add_round_key(m, 0);                               // 메시지와 0라운드 키를 xor한다.
    for (int round = 1; round < ROUND - 1; round++) {  // 1~9라운드
        substitue(m);
        shift_row(m);
        mix_column(m);
        add_round_key(m, round);
    }
    // 마지막 라운드
    substitue(m);
    shift_row(m);
    add_round_key(m, ROUND - 1);  // 10라운드 키와 메시지를 xor한다.
}

// AES 복호화 함수
void AES128::AES::decrypt(unsigned char *m) const {
    add_round_key(m, ROUND - 1);                       // 메시지와 10라운드 키를 xor한다.
    for (int round = ROUND - 2; round > 0; round--) {  // 9~1라운드
        inv_shift_row(m);
        inv_substitue(m);
        add_round_key(m, round);
        inv_mix_column(m);
    }
    inv_shift_row(m);
    inv_substitue(m);
    add_round_key(m, 0);  // 0라운드 키와 메시지를 xor한다.
}

template <class Cipher>
void AES128::CipherMode<Cipher>::key(const unsigned char *p) {
    cipher_.key(p);
}

template <class Cipher>
void AES128::CBC<Cipher>::iv(const unsigned char *p) {
    memcpy(this->iv_, p, 16);
}

template <class Cipher>
void AES128::CBC<Cipher>::encrypt(unsigned char *p, int sz /*블록 사이즈*/) const {
    // 순차적임
    assert(sz % 16 == 0);
    for (int i = 0; i < 16; i++) {
        p[i] ^= this->iv_[i];  // P0 ^ IV
    }
    for (int j = 1; j < sz / 16; j++) {
        this->cipher_.encrypt(p);  // xor한 결과16바이트 암호화
        for (int i = 0; i < 16; i++, p++) {
            *(p + 16) ^= *p;  // P1 ^ C0 , xor수행
        }
    }
    this->cipher_.encrypt(p);  // 마지막 xor한 결과 암호화
}

template <class Cipher>
void AES128::CBC<Cipher>::decrypt(unsigned char *p/*암호문*/, int sz) const {
    //병행 프로그래밍 가능
    assert(sz % 16 == 0);
    unsigned char buf[sz];
    memcpy(buf, p, sz);

    //Routine 1. decrypt
    for(int i = 0; i < sz; i+=16) {
        this->cipher_.decrypt(p + i);
    }
    #pragma omp parallel for
    //Routine 2. IV xor C0
    for(int i = 0; i < 16; i++) {
        *p++ ^= this->iv_[i];
    }
    #pragma omp parallel for
    //Routine 3. Other Decrypt text xor with Cipher Text
    for(int i = 0; i < sz - 16; i++) {
        *p++ ^= buf[i];
    }
}

template<class Cipher>
void AES128::GCM<Cipher>::doub(unsigned char* p) {// GCM 갈루아 필드에서 ⊗2연산
    //p는 16바이트의 최고차항이 맨 우측인 형식의 머리부분
	bool bit1 = p[15] & 1;//최고차항의 bit가 1인지 여부
	for(int i = 15; i > 0; i--) {
		//우측 쉬프트 연산
		p[i] = (p[i] >> 1) | (p[i - 1] << 7);
	}
	p[0] >>= 1;
	if(bit1) p[0] ^= 0b11100001;
}

template<class Cipher>
void AES128::GCM<Cipher>::gf_mul(unsigned char *x, unsigned char *H) {//GCM 갈루아 필드에서 mult_H 함수
    //H :   ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ ㅁ
    //bit : 8  8  8  8  8  8 8  8  8  8  8  8  8  8 8  8 -> 128 bit
    unsigned char z[16] = { 0 };//결과를 저장하는 임시 변수
    for(int i = 0; i < 16; i++) {//모든 128비트 H순회
        for(int j = 0; j < 8; j++) {//H의 모든 비트 확인
            if(H[i] & 1 << (7 - j)) {//bit단위로 H를 검사한다.
                for(int k = 0; k < 16; k++) {
                    z[k] ^= x[k];//z에 현재의 x 값을 더함
                }
            }
            doub(x);//x, 2x, 4x, 8x ...
        }
    }
    memcpy(x, z, 16);
}

template<class Cipher>
void AES128::GCM<Cipher>::iv(const unsigned char *p) {
    memcpy(this->iv_, p, 12);
}

template<class Cipher>
void AES128::GCM<Cipher>::iv(const unsigned char *p, int from, int sz) {
    memcpy(this->iv_ + from, p, sz);
}

template<class Cipher>
void AES128::GCM<Cipher>::aad(unsigned char *p, int sz) {
    aad_ = std::vector<unsigned char>{p, p + sz};
    //Save len(Auth)
    UTIL::mpz_to_bnd(aad_.size() * 8/*길이값의 비트수*/, lenAC_, lenAC_ + 8);
    //16byte의 배수가 될때까지 Padding
    while(aad_.size() % 16) {
        aad_.push_back(0);
    }
}

template<class Cipher>
void AES128::GCM<Cipher>::xor_with_enc_ivNcounter(unsigned char *p/*xor target*/, int sz/*블록의 크기*/, int ctr/*Counter*/) {
    unsigned char ivNcounter[16];
    //iv || Counter
    memcpy(ivNcounter,this->iv_, 12);//iv
    UTIL::mpz_to_bnd(ctr, ivNcounter + 12, ivNcounter + 16);// || ctr
    this->cipher_.encrypt(ivNcounter);//E(iv || Counter, K)
    //p ^ Cipher Text
    for(int i = 0; i < sz; i++) {
        p[i] ^= ivNcounter[i];
    }
}

template<class Cipher>
std::array<unsigned char, 16> AES128::GCM<Cipher>::generate_auth(unsigned char *p/*암호문*/, int sz/*평문의 총 바이트수 16바이트의 배수가 되지 않아도됨*/) { //16바이트의 인증 태그 생성
    std::array<unsigned char, 16> Auth;
    unsigned char H[16] = { 0 };
    this->cipher_.encrypt(H);//This is H Using mult_H
    
    //인증 태그 생성
    if(!aad_.empty()) {
        //인증 태그 전처리
        gf_mul(&aad_[0], H);//mult_H
        //만약 인증 데이터가 16바이트 보다 크다면 처리
        for(int i = 0; i < aad_.size() - 16; i += 16) {
            for(int j = 0; j < 16; j++) {
                aad_[i + 16 + j]/*다음 인증 데이터값에 저장*/ ^= aad_[i + j]/*현재 인증 데이터*/;
            }
            gf_mul(&aad_[i+16]/*xor한 인증 데이터*/, H);
        }
        std::copy(aad_.end() - 16, aad_.end(), Auth.begin());// 마지막 데이터를 Auth에 복사함
    }
    
    for(int i = 0; i < sz; i+= 16) {//모든 암호문 블록 순회
        for(int j = 0; j < std::min(16, sz - i); j++) {// ^ Cipher Text
            Auth[j] ^= p[i + j];
        }
        gf_mul(&Auth[0], H);
    }

    //len(C)의 비트수
    UTIL::mpz_to_bnd(sz * 8, lenAC_ + 8, lenAC_ + 16);//len(A)의 비트수 || len(C)의 비트수
    //( len(A) || len(C) ) ^ 인증 중간값
    for(int i = 0; i < 16; i++) {
        Auth[i] ^= lenAC_[i];
    }
    gf_mul(&Auth[0], H);//최종적인 인증 중간 값과 mult_H연산
    xor_with_enc_ivNcounter(&Auth[0],16, 1);//첫번째 E(IV || 1(ctr), K) ^ 최종 직전 인증 데이터
    return Auth;
}

template<class Cipher>
std::array<unsigned char, 16> AES128::GCM<Cipher>::encrypt(unsigned char *p, int sz/*평문의 총 바이트수 16바이트의 배수가 되지 않아도 됨*/) {
    //p가 가리키는 위치에 암호문을 덮어쓰고, 인증 태그를 리턴한다.
    for(int i = 0; i < sz; i += 16) {//평문 순회
        xor_with_enc_ivNcounter(p + i, std::min(16, sz - i), i/16 + 2 /*Counter*/);
    }
    return generate_auth(p/*암호문*/, sz/*평문의 총바이트수*/);
}

template<class Cipher>
std::array<unsigned char, 16> /*Auth Tag*/ AES128::GCM<Cipher>::decrypt(unsigned char *p, int sz) {
    //복호화 시에는 인증 태그 생성이 먼저
    auto a = generate_auth(p, sz);
    for(int i = 0; i < sz; i += 16) {
        xor_with_enc_ivNcounter(p + i, std::min(16, sz - i), i/16 + 2);
    }
    return a;
}