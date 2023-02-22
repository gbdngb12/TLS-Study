#pragma once
#include <gmpxx.h>
#include <jsoncpp/json/json.h>
#include <ios>
#include <istream>
#include <vector>
#include <iomanip>
#include <array>
#include <utility>
#include <cassert>

#include "key_exchange.h"
#include "util.h"


namespace AUTH {
class RSA {
   public:
    RSA() = default;
    RSA(int key_size);
    RSA(mpz_class e, mpz_class d, mpz_class K);
    mpz_class sign(mpz_class m);    // 개인키 d 암호화(서명)
    mpz_class decode(mpz_class m);  // 공개키 e 암호화(서명 검증)
    mpz_class encode(mpz_class m);  // 개인키 d 암호화(서명)
    mpz_class K, e;                 // 공개키K, e
    void set_key(mpz_class e, mpz_class d, mpz_class K);
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


namespace DER {
enum class Class {
    UNIVERSAL,
    APPLICATION,
    CONTEXT_SPECIFIC,
    PRIVATE
};

enum class PC {
    PRIMITIVE,
    CONSTRUCTED
};

enum class Tag {
    EOC,                // 0
    BOOLEAN,            // 1
    INTEGER,            // 2
    BIT_STRING,         // 3
    OCTET_STRING,       // 4
    NULL_TYPE,          // 5
    OBJECT_IDENTIFIER,  // 6
    OBJECT_DESCRIPTOR,  // 7
    EXTERNAL,           // 8
    REAL,               // 9
    ENUMERATED,         // 10
    EMBEDDED_PDV,       // 11
    UTF8STRING,         // 12
    RELATIVE_OID,       // 13
    RESERVED1,          // 14
    RESERVED2,          // 15
    SEQUENCE,           // 16
    SET,                // 17
    NUMERIC_STRING,     // 18
    PRINTABLE_STRING,   // 19
    T61_STRING,         // 20
    VIDEOTEX_STRING,    // 21
    IA5_STRING,         // 22
    UTCTIME,            // 23
    GENERALIZED_TIME,   // 24
    GRAPHIC_STRING,     // 25
    VISIBLE_STRING,     // 26
    GENERAL_STRING,     // 27
    UNIVERSAL_STRING,   // 28
    CHARACTER_STRING,   // 29
    BMP_STRING          // 30
};

struct Type {
    Tag tag;
    Class cls;
    PC pc;
};

/*!
 * @brief 한 바이트를 읽어 Type 구조체를 반환 하는 함수
 * @param       c   인증서 DER의 한 바이트
 * @result      인증서 DER의 Type 구조체
 */
Type read_type(unsigned char c);

/*!
 * @brief  인증서 DER의 Length 시작지점 스트림에서 Contents의 길이를 읽어 반환하는 함수
 * @param       is   인증서 DER의 Length 시작지점의 스트림
 * @result      DER Contents의 길이
 */
int read_length(std::istream& is);

/*!
 * @brief  DER Contents Stream을 Vector로 변환하는 함수
 * @param       is   인증서 DER의 Contents 시작지점의 스트림
 * @param       len Contents의 길이
 * @result      DER Contents의 char vector
 */
std::vector<unsigned char> read_value(std::istream& is, int len);

/*!
 * @brief       DER Contents vector값을 tag 형식으로 Json Value를 만드는 함수
 * @param       tag   DER Contents의 형식
 * @param       v DER Contents의 vector
 * @result      DER Contents의 Json::Value
 */
Json::Value type_change(Tag tag, std::vector<unsigned char> v);


/*!
 * @brief       복합적인 DER Contents중 한 부분을 읽는 함수
 * @param       is   복합적인 DER의 Contents 시작지점의 스트림
 * @result      복합적인 DER Contents의 Json::Value
 */
Json::Value read_constructed(std::istream& is, int length);

/*!
 * @brief       DER Contents를 Json으로 변환하는 함수
 * @param       is   인증서 DER의 Contents 시작지점의 스트림
 * @result      DER Contents의 Json::Value
 */
Json::Value der_to_json(std::istream& is);

/*!
 * @brief       PEM 인증서에서 base64 인코딩된 DER 값을 추출 하는 함수
 * @param       is   PEM 인증서의 시작지점의 스트림
 * @result      PEM 인증서에서 base64 인코딩된 DER값 문자열
 */
std::string get_certificate_core(std::istream& is);

/*!
 * @brief       jv[0][0][6][1](TBS Certificate)을 처리해 공개키 e, K를 반환 하는 함수
 * @param       s   TBS Certificate 문자열
 * @result      공개키 e, K 배열
 */
std::array<mpz_class, 2> process_bitstring(std::string s);

/*!
 * @brief       DER Json Value로부터 공개키 K, e, Sign을 반환 하는 함수
 * @param       jv   DER Json Value
 * @result      공개키 K,e, Sign 배열
 */
std::array<mpz_class, 3> get_pubkeys(const Json::Value& jv);

/**
 * @brief RSA 키 파일(pem)을 읽어 키 stream을 반환한다.
 * @param is key.pem 파일
 * @return [K, e, d] 공개키 K, e 비밀키 d
*/
std::array<mpz_class, 3> get_keys(std::istream& is);;//is key.pem

/**
 * @brief PEM Json에서 공개키, 비밀키 쌍을 읽어 반환한다.
 * @param jv PEM Json
 * @return [K, e, d] 공개키 K, e 비밀키 d
*/
std::array<mpz_class, 3> get_keys(const Json::Value &jv);
/**
 * @brief PEM 인증서 파일을 읽어 Json으로 변환한다.
 * @param is PEM 인증서 Input Stream
 * @return PEM 인증서 Json
*/
Json::Value pem_to_json(std::istream& is);
}  // namespace BER

