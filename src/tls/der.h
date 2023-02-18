#pragma once
#include <jsoncpp/json/json.h>

#include <ios>
#include <istream>
#include <vector>
#include <iomanip>

#include "util.h"

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
 * @brief       6bits값을 base64 char로 치환
 * @param       n
 * @result      base64로 인코딩된 char
 */
char bits_to_char(unsigned char n);

/*!
 * @brief       base64 char값을 6bits로 복구
 * @param       c   
 * @result      base64 디코딩된 char
 */
unsigned char char_to_bits(char c);

/*!
 * @brief       base64 인코딩
 * @param       v 인코딩할 unsigned char vector
 * @result      base64 인코딩한 string
 */
std::string base64_encode(std::vector<unsigned char> v);

/*!
 * @brief       base64 디코딩
 * @param       s 디코딩할 string
 * @result      base64 디코딩한 unsigned char vector
 */
std::vector<unsigned char> base64_decode(std::string s);
}  // namespace BER