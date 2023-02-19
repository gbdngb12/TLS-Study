#include "util.h"
using namespace std;

// n보다 큰 최초의 소수를 리턴한다.
mpz_class UTIL::nextprime(mpz_class n) {
    mpz_class r;
    mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
    return r;
}

// base^exp mod mod 를 구한다.
mpz_class UTIL::powm(mpz_class base, mpz_class exp, mpz_class mod) {
    mpz_class r;
    assert(mod);
    mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return r;
}

// byte 길이의 소수를 리턴한다.
mpz_class UTIL::random_prime(unsigned byte) {
    unsigned char arr[byte];
    std::uniform_int_distribution<int> di(0, 0xff);
    // 0 ~ 255의 임의의 정수를 균등한 확률로 생성
    std::random_device rd;
    // arr에 랜덤한 값을 가지는 배열 저장
    for (int i = 0; i < byte; i++) {
        arr[i] = di(rd);
    }
    // z에 랜덤한 수의 바로 다음에 오는 소수 설정
    auto z = UTIL::nextprime(UTIL::bnd_to_mpz(arr, arr + byte));
    for (int i = 0; i < byte; i++) {
        arr[i] = 0xff;
    }
    // 만약 바로 다음오는 소수가 byte로 표현 가능한 최대치보다 클경우
    // 다시 생성
    if (z > UTIL::bnd_to_mpz(arr, arr + byte)) {
        return UTIL::random_prime(byte);
    } else {  // 만약 범위안에 존재할 경우 그값 리턴
        return z;
    }
}

char BASE64::bits_to_char(unsigned char n) {
    if (n < 26) return 'A' + n;
    if (n < 52) return 'a' + (n - 26);
    if (n < 62) return '0' + (n - 52);
    return n == 62 ? '+' : '/';
}

unsigned char BASE64::char_to_bits(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c) return c - 'a' + 26;
    if ('0' <= c) return c - '0' + 52;
    return c == '+' ? 62 : 63;
}

string BASE64::base64_encode(vector<unsigned char> v) {
    string s;
    int padding = (3 - v.size() % 3) % 3;
    for(int i = 0; i < padding; i++) v.push_back(0);
    for(int i = 0; i < v.size(); i += 3) {
        s += BASE64::bits_to_char((v[i] & 0b11111100) >> 2);
		s += BASE64::bits_to_char((v[i] & 0b00000011) << 4 | (v[i+1] & 0b11110000) >> 4);
		s += BASE64::bits_to_char((v[i+1] & 0b00001111) << 2 | (v[i+2] & 0b11000000) >> 6);
		s += BASE64::bits_to_char(v[i+2] & 0b00111111);
    }
    for(int i = 0; i < padding; i++) s[s.size() - 1 - i] = '=';
    return s;
}

vector<unsigned char> BASE64::base64_decode(string s) {
    int padding = 0;
	for(int i=0; s[s.size()-1-i] == '='; i++) padding++;
	unsigned char bit[4];
	vector<unsigned char> v;
	for(int i=0; i<s.size(); i+=4) {
		for(int j=0; j<4; j++) bit[j] = BASE64::char_to_bits(s[i+j]);
		v.push_back(bit[0] << 2 | bit[1] >> 4);
		v.push_back(bit[1] << 4 | bit[2] >> 2);
		v.push_back(bit[2] << 6 | bit[3]);
	}
	for(int i=0; i<padding; i++) v.pop_back();
	return v;
}

mpz_class UTIL::str_to_mpz(std::string s) {
    std::stringstream ss; char c; string r = "0x";
    ss << s;
    while(ss >> setw(2) >> s >> c/*c는 ':'를 저장하는 공간*/) r += s;
    return mpz_class{r};
}