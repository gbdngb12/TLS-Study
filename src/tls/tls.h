#pragma once
#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "aes128.h"  //암호 알고리즘
#include "auth.h"    //인증 알고리즘
#include "hash.h"    //해쉬 알고리즘
#include "util.h"

namespace TLS {
template <bool SV = true>
class TLS {
   public:
    /*!
    @brief TLS Header의 content_type, HandShake Header의 HandShake Type을 가져온다.
    @param s TLS Header Struct 의 String
    @return <TLS.Content_type, HandShake.type>
    */
    std::pair<int, int> get_content_type(const std::string &s);

    /*!
    @brief 암호화된 TLS Recored를 복호화한다.
    @param s 암호화된 TLS Header Struct 의 String
    @return 성공시 복호화된 string 반환, 실패시 has_value() -> false
    */
    std::optional<std::string> decode(std::string &&s = "");

    /*!
    @brief 암호화된 TLS Record를 생성 한다.
    @param s 암호화 되지 않은 TLS Record의 String
    @param type TLS Type default -> 0x17 : Encrypted Data
    @return <TLS.Content_type, HandShake.type>
    */
    std::string encode(std::string &&s = "", int type = 0x17);

    /*!
    @brief client hello HandShake 함수, 서버 -> Client Hello 메시지 분석, 클라이언트 -> Client Hello 메시지 생성
    @param s 빈문자열 이라면 Client Hello 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(Client Hello 메시지), 오류(alert 메시지)
    */
    std::string client_hello(std::string &&s = "");

    /*!
    @brief server hello HandShake 함수, 서버 -> Server Hello 메시지 분석, 클라이언트 -> Server Hello 메시지 생성
    @param s 빈문자열 이라면 Server Hello 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(Server Hello 메시지), 오류(alert 메시지)
    */
    std::string server_hello(std::string &&s = "");

    /*!
    @brief server_certificate HandShake 함수, 서버 -> server_certificate 메시지 분석, 클라이언트 -> server_certificate 메시지 생성
    @param s 빈문자열 이라면 server_certificate 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(server_certificate 메시지), 오류(alert 메시지)
    */
    std::string server_certificate(std::string &&s = "");

    /*!
    @brief server_key_exchange HandShake 함수, 서버 -> server_key_exchange 메시지 분석, 클라이언트 -> server_key_exchange 메시지 생성
    @param s 빈문자열 이라면 server_key_exchange 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(server_key_exchange 메시지), 오류(alert 메시지)
    */
    std::string server_key_exchange(std::string &&s = "");

    /*!
    @brief server_hello_done HandShake 함수, 서버 -> server_hello_done 메시지 분석, 클라이언트 -> server_hello_done 메시지 생성
    @param s 빈문자열 이라면 server_hello_done 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(server_hello_done 메시지), 오류(alert 메시지)
    */
    std::string server_hello_done(std::string &&s = "");

    /*!
    @brief client_key_exchange HandShake 함수, 서버 -> client_key_exchange 메시지 분석, 클라이언트 -> client_key_exchange 메시지 생성
    @param s 빈문자열 이라면 client_key_exchange 메시지 생성, 문자가 존재한다면 분석
    @return 서버 -> 정상 분석(""), 오류(alert 메시지), 클라이언트 -> 정상 생성(client_key_exchange 메시지), 오류(alert 메시지)
    */
    std::string client_key_exchange(std::string &&s = "");

    /*!
    @brief Change Cipher Spec 메시지 생성 또는 분석 함수
    @param s 빈문자열 이라면 Change Cipher Spec 메시지 생성, 문자가 존재한다면 분석
    @return 분석 -> 정상 분석(""), 오류(alert 메시지), 생성 -> 정상 생성(Change Cipher Spec 메시지), 오류(alert 메시지)
    */
    std::string change_cipher_spec(std::string &&s = "");

    /*!
    @brief finished HandShake 메시지 생성 또눈 분석 함수
    @param s 빈문자열 이라면 finished 메시지 생성, 문자가 존재한다면 분석
    @return 분석 -> 정상 분석(""), 오류(alert 메시지), 생성 -> 정상 생성(finished 메시지), 오류(alert 메시지)
    */
    std::string finished(std::string &&s = "");

    /*!
    @brief alert 메시지 분석 함수
    @param s 분석할 alert 메시지 String
    @return alert.desc 값 리턴과 std::cerr로 오류 메시지 출력
    */
    int alert(std::string &&s = "");

    /*!
    @brief alert 메시지 생성 함수
    @param level alert 메시지의 level
    @param desc alert 메시지의 description
    @return 생성한 alert메시지의 String
    */
    std::string alert(uint8_t level, uint8_t desc);

   protected:
    AES128::GCM<AES128::AES> aes_[2];  // 0 : client, 1 : server
    mpz_class enc_seq_num_ = 0 /*암호화 순서 번호*/,
              dec_seq_num_ = 0 /*복호화 순서 번호*/,
              prv_key_ = UTIL::random_prime(31);  // 타원 곡선의 비밀키
    AUTH::ECDSA::EC_Field secp256r1_{
        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_mpz,                       // a
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_mpz,                       // b
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff_mpz                        // mod p
    };                                                                                                // secp256r1 타원곡선정의
    AUTH::ECDSA::EC_Point G_{0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_mpz,  // x
                             0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_mpz,  // y
                             secp256r1_},                                                             // Generator Point
        P_{G_ * prv_key_};                                                                            // 타원 곡선의 공개키
    std::array<unsigned char, 32> session_id_, server_random_, client_random_;
    std::vector<unsigned char> master_secret_;  // 키 교환으로 생성 해야한다.(중간 단계 값)
    // premaster_secret는 서버 또는 클라이언트로부터 수신한 공개키값에 자신의 비밀키를 곱한후 x좌표
    std::string accumulated_handshakes_;  // HandShake과정에서 누적 기록
    /*!
    @brief TLS Header를 제외한 모든 HandShake Message를 저장한다.
    @param s TLS Header를 포함한 Packet String
    @return TLS Header를 포함한 Packet String
    */
    std::string accumulate(const std::string &s);  // TLS Header를 포함한 Packet을
    static std::string certificate_;               // RSA 인증서 저장
    static AUTH::RSA rsa_;                         // 인증서의 공개키 값 저장

   private:
    /*!
    @brief 타원곡선 좌표가 변조되지 않았음을 증명하기위해 서명을 생성한다.
    @param pub_key 타원곡선 공개키 정보
    @param sign 서명을 저장할 위치
    */
    void generate_signature(unsigned char* pub_key, unsigned char* sign);

    /*!
    @brief premaster_secret으로부터 master_secret값을 구하고 이를 통해 키를 확장한다.
    @param premaster_secret premaster_secret값
    */
   void derive_keys(mpz_class premaster_secret);
};
}  // namespace TLS
