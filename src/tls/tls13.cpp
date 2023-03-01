#include "tls13.h"
#pragma pack(1)
#include <nettle/curve25519.h>
using namespace std;
using namespace UTIL;

template class TLS13::TLS13<true>;
template class TLS13::TLS13<false>;

template <bool SV>
void TLS13::TLS13<SV>::protect_handshake() {  // server hello 직후에 호출
    hkdf_.zero_salt();
    uint8_t psk[HASH::SHA2::output_size] = {0} /*미리 공유한키는 현재 없음*/, pre[32];
    auto early_secret = hkdf_.extract(psk, HASH::SHA2::output_size);
    hkdf_.salt(&early_secret[0], early_secret.size());
    auto tmp_salt = hkdf_.derive_secret("derived", "");
    hkdf_.salt(&tmp_salt[0], tmp_salt.size());
    UTIL::mpz_to_bnd(premaster_secret_, pre, pre + 32);
    auto handshake_secret = hkdf_.extract(pre, 32);

    finished_key_ = set_aes(handshake_secret, "c hs traffic", "s hs traffic");
    hkdf_.salt(&handshake_secret[0], handshake_secret.size());
    tmp_salt = hkdf_.derive_secret("derived", "");
    hkdf_.salt(&tmp_salt[0], tmp_salt.size());
    this->master_secret_ = hkdf_.extract(psk, HASH::SHA2::output_size);
}

template <bool SV>
array<vector<uint8_t>, 2> TLS13::TLS13<SV>::set_aes(std::vector<uint8_t> salt, std::string client_label, std::string server_label) {
    this->enc_seq_num_ = 0;
    this->dec_seq_num_ = 0;
    hkdf_.salt(&salt[0], salt.size());
    array<vector<unsigned char>, 2> secret /**traffic secret*/, finished_key /**handshake 에서 사용하는 finished key*/;
    secret[0] = hkdf_.derive_secret(client_label, this->accumulated_handshakes_);  // traffic secret
    secret[1] = hkdf_.derive_secret(server_label, this->accumulated_handshakes_);  // traffic secret
    for (int i = 0; i < 2; i++) {
        /**
         * @brief generate AES key, iv
         * @note write_key = salt(traffic_secret), expand_label("key", "", key_length)
         * @note write_iv = salt(traffic_secret), expand_label("iv", "", iv_length);
         */
        hkdf_.salt(&secret[i][0], secret[i].size());
        auto key = hkdf_.expand_label("key", "", 16);
        auto iv = hkdf_.expand_label("iv", "", 12);
        this->aes_[i].key(&key[0], key.size());  // set AES key
        this->aes_[i].iv(&iv[i], iv.size());     // set AES iv

        /**
         * @brief generate finished_key
         * @note finished_key = salt(traffic_secret), expand_label("finished", "", key_size)
         */
        finished_key[i] = hkdf_.expand_label("finished", "", HASH::SHA2::output_size);
    }
    return finished_key;
}

template <bool SV>
void TLS13::TLS13<SV>::protect_data() {  // server finished 직후에 호출
    set_aes(this->master_secret_, "c ap traffic", "s ap traffic");
}

template <bool SV>
string TLS13::TLS13<SV>::client_ext() {
    /**
     * @struct client extension 메시지 구조
     */
    struct Ext {
        uint8_t extension_length[2] = {0, 0}; /** @brief extension total length[2] */

        /**
         * @struct extension 1 : key exchange algorithm supported_group extension
         */
        uint8_t supported_group[2] = {0, 10};            /** @brief extension type */
        uint8_t supported_group_length[2] = {0, 6};      /** @brief extension total length */
        uint8_t supported_group_list_length[2] = {0, 4}; /** @brief supported group length */
        uint8_t secp256r1[2] = {0, 23};                  /** @brief 0x0017 */
        uint8_t x255[2] = {0, 29};                       /** @brief 0x001d */

        /**
         * @struct extension 2 : ec_point_format_extension
         */
        uint8_t ec_point_format[2] = {0, 11};       /** @brief extension type*/
        uint8_t ec_point_format_length[2] = {0, 2}; /** @brief extension total length */
        uint8_t ec_length = 1;                      /** @brief length field*/
        uint8_t non_compressed = 0;                 /** @brief compress foramt*/

        /**
         * @struct extension 3 : key_share_extension
         */
        uint8_t key_share[2] = {0, 51};             /** @brief extension type */
        uint8_t key_share_length[2] = {0, 107};     /** @brief extension total length*/
        uint8_t client_key_share_len[2] = {0, 105}; /** @brief total length */

        uint8_t secp256r1_key[2] = {0, 23}; /** @brief algorithm type*/
        uint8_t key_length[2] = {0, 65};    /** @brief key length*/
        /**
         * @brief ECDHE Parameter */
        uint8_t type = 4;
        uint8_t x[32], y[32]; /** @brief key*/

        uint8_t x25519[2] = {0, 29};      /** @brief algorithm type */
        uint8_t key_length2[2] = {0, 32}; /** @brief key length*/
        uint8_t x2[32];                   /** @brief key */

        /**
         * @struct extension 4 : supported_version extension
         */
        uint8_t supported_version[2] = {0, 0x2b};     /** @brief extension type */
        uint8_t supported_version_length[2] = {0, 5}; /** @brief extension total length */
        uint8_t supported_version_list_length = 4;    /** @brief total length*/
        uint8_t supported_versions[4] = {3, 4, 3, 3}; /** @brief 1.3, 1.2 */

        /**
         * @struct extension 5 : psk_exchange_mode extension
         */
        uint8_t psk_mode[2] = {0, 0x2d};    /** @brief extension type */
        uint8_t psk_mode_length[2] = {0, 2} /** @brief extension totla length*/
        uint8_t psk_mode_llength = 1;
        uint8_t psk_with_ecdhe = 1; /** psk = 0, psk_dhe = 1*/

        /**
         * @struct extension 6 : signature_algorithm extension
         */
        uint8_t signature_algorithm[2] = { 0, 13 };/** @brief extension type */
        uint8_t signature_algorithm_length[2] = { 0, 8 }; /** @brief extension length */
        uint8_t signature_alg_len[2] = { 0, 6 }; /** @brief 6 / 2 = 3개*/
        /** 
         * @brief rsa_pss_rsae_sha256(0x0804)
         * @brief rsa_pkcs1_sha256(0x0401)
         * @brief ecdsa_secp256r1_sha256(0x0403)
        */
        uint8_t signature[4] = { 8, 4, 4, 1, 4, 3}; 

    } ext;

    mpz_to_bnd(this->P_.x, ext.x, ext.x + 32); //secp256r1 좌표 셋팅
    mpz_to_bnd(this->P_.y, ext.y, ext.y + 32); //P_는 tls 1.2의 멤버
    mpz_to_bnd(sizeof(Ext) - 2/*extension_length Field[2]*/, ext.extension_length, ext.extension_length + 2);

    mpz_to_bnd(this->prv_key_, prv_, prv_ + 32);
    curve25519_mul_g(ext.x2, prv_);/** ext.x2 <= G(=9) * prv_ x25519 x좌표 셋팅 */
    return struct_to_str(ext);
}

#pragma pack()