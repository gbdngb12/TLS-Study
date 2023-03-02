#pragma once
#include <functional>

#include "tls.h"
namespace TLS13 {

template <bool SV>
class TLS13 : public TLS::TLS<SV> {
   public:
    std::string client_hello(std::string &&s = "");
    std::string server_hello(std::string &&s = "");
    /**
     * @brief handshake를 수행한다.
     */
    bool handshake(std::function<std::optional<std::string>()> read_f, std::function<void(std::string)> write_f);
    std::string finished(std::string &&s = "");
    std::string certificate_verify();
    std::optional<std::string> decode(std::string &&s);
    std::string encode(std::string &&s, int type = 23);
    std::string server_certificate13();

   protected:
    HASH::HKDF<HASH::SHA2> hkdf_;
    mpz_class premaster_secret_; /**TLS1.3인경우 Hello Message 이후에 0이 아닌값으로 셋팅 키교환 알고리즘으로 합의된 키 ECDHE*/
    /**
     * @brief client extension 메시지를 생성한다.
     * @return client extension 메시지
     */
    std::string client_ext();
    /**
     * @brief server extension 메시지를 생성한다.
     * @return server extension 메시지
     */
    std::string server_ext();
    /**
     * @brief encrypted extension 메시지를 생성한다.
     * @return encrypted extension 메시지
     */
    std::string encrypted_extension();
    /**
     * @brief client extension 메시지를 분석해 TLS 1.3으로 통신가능한지 확인한다.
     * @return TLS1.3 통신가능/불가능
     */
    bool client_ext(unsigned char *p);
    /**
     * @brief server extension 메시지가 있는지 분석한다.
     * @param p server extension pointer
     * @return server extension 메시지가 존재/존재하지 않는다.
     */
    bool server_ext(unsigned char *p);

   private:
    uint8_t prv_[32] = UTIL::random_prime(32), echo_id_[32];
    std::string ecdsa_certificate_;/**ECDSA DEM 인증서*/
    /**
     * @brief application traffic secret으로 데이터 암호화
    */
    void protect_data();
    /**
     * @brief handshake traffic secret으로 데이터 암호화
    */
    void protect_handshake();
    /**
     * @brief handshake traffic secret, finished_key값을 설정하는 함수
     * @param salt salt값
     * @param client_label client label
     * @param server_label server label
     * @return finished_key[client, server]
    */
    std::array<std::vector<uint8_t>, 2> set_aes(std::vector<uint8_t> salt, std::string client_label, std::string server_label);
    /**
     * @brief finished 메시지를 전송할때 이값을 salt로하여 hash한 값을 붙힌다.(무결성 검증)
    */
    std::array<std::vector<uint8_t>, 2> finished_key_;
    /**
     * @brief supported_group extension이 서버가 제공가능한지 확인한다.
     * @param p supported_group extension의 pointer
     * @param len supported_group extension의 length
     * @return secp256r1을 지원할 경우 true
    */
    bool supported_group(unsigned char*p, int len);

    /**
     * @brief 타원곡선 좌표의 형식이 무압축인지 확인한다.
     * @param p point_format의 pointer
     * @param len point_format_extension의 length
     * @return 무압축이면 true
    */
    bool point_format(unsigned char*p, int len);

    /**
     * @brief key_share 함수에서 호출, 타원곡선의 좌표를 세팅한다.
     * @param p algorithm type Pointer
     * @return 지원하는 키 알고리즘이 있다면 세팅하고 참 리턴, 없으면 거짓
    */
    bool sub_key_share(unsigned char*p);

    /**
     * @brief key_share_extension을 확인한다.
     * @param p key_share_extension pointer
     * @param len key_share_extension length
     * @return 지원하는 key_share_algorithm이 있다면 참리턴.
    */
    bool key_share(unsigned char*p, int len);

    /**
     * @brief supported_version extension을 확인한다.
     * @param p supported_version pointer
     * @param len supported_version length
     * @return TLS 1.3을 지원하면 true를 리턴한다.
    */
    bool suppotred_version(unsigned char *p, int len);

    void derive_keys(mpz_class premaster_secret);
    std::optional<std::string> decode13(std::string &&s);
    std::string encode13(std::string &&s, int type = 23);

};
}  // namespace TLS13