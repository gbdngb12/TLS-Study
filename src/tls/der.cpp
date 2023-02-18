#include "der.h"
using namespace std;

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

char DER::bits_to_char(unsigned char n) {
    if (n < 26) return 'A' + n;
    if (n < 52) return 'a' + (n - 26);
    if (n < 62) return '0' + (n - 52);
    return n == 62 ? '+' : '/';
}

unsigned char DER::char_to_bits(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c) return c - 'a' + 26;
    if ('0' <= c) return c - '0' + 52;
    return c == '+' ? 62 : 63;
}

string DER::base64_encode(vector<unsigned char> v) {
    string s;
    int padding = (3 - v.size() % 3) % 3;
    for(int i = 0; i < padding; i++) v.push_back(0);
    for(int i = 0; i < v.size(); i += 3) {
        s += DER::bits_to_char((v[i] & 0b11111100) >> 2);
		s += DER::bits_to_char((v[i] & 0b00000011) << 4 | (v[i+1] & 0b11110000) >> 4);
		s += DER::bits_to_char((v[i+1] & 0b00001111) << 2 | (v[i+2] & 0b11000000) >> 6);
		s += DER::bits_to_char(v[i+2] & 0b00111111);
    }
    for(int i = 0; i < padding; i++) s[s.size() - 1 - i] = '=';
    return s;
}

vector<unsigned char> DER::base64_decode(string s) {
    int padding = 0;
	for(int i=0; s[s.size()-1-i] == '='; i++) padding++;
	unsigned char bit[4];
	vector<unsigned char> v;
	for(int i=0; i<s.size(); i+=4) {
		for(int j=0; j<4; j++) bit[j] = DER::char_to_bits(s[i+j]);
		v.push_back(bit[0] << 2 | bit[1] >> 4);
		v.push_back(bit[1] << 4 | bit[2] >> 2);
		v.push_back(bit[2] << 6 | bit[3]);
	}
	for(int i=0; i<padding; i++) v.pop_back();
	return v;
}