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
         * @struct extension 1 : key exchange supported_group extension
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
        uint8_t signature_algorithm[2] = {0, 13};       /** @brief extension type */
        uint8_t signature_algorithm_length[2] = {0, 8}; /** @brief extension length */
        uint8_t signature_alg_len[2] = {0, 6};          /** @brief 6 / 2 = 3개*/
        /**
         * @brief rsa_pss_rsae_sha256(0x0804)
         * @brief rsa_pkcs1_sha256(0x0401)
         * @brief ecdsa_secp256r1_sha256(0x0403)
         */
        uint8_t signature[4] = {8, 4, 4, 1, 4, 3};

    } ext;

    mpz_to_bnd(this->P_.x, ext.x, ext.x + 32);  // secp256r1 좌표 셋팅
    mpz_to_bnd(this->P_.y, ext.y, ext.y + 32);  // P_는 tls 1.2의 멤버
    mpz_to_bnd(sizeof(Ext) - 2 /*extension_length Field[2]*/, ext.extension_length, ext.extension_length + 2);

    mpz_to_bnd(this->prv_key_, prv_, prv_ + 32);
    curve25519_mul_g(ext.x2, prv_); /** ext.x2 <= G(=9) * prv_ x25519 x좌표 셋팅 */
    return struct_to_str(ext);
}

template <bool SV>
bool TLS13::TLS13<SV>::client_ext(unsigned char *p) {
    // extension을 확인해 1.3으로 통신가능한지 확인한다.
    int total_len = *p++ * 0x100 + *p++;
    bool check_ext[5] = {false};  // supported_group, ec_point_format, key_share, supported_version, psk_exchange_modes

    for (unsigned char *q = p; p < q + total_len;) {  // Check the extension
        int type = *p++ * 0x100 + *p++;
        int len = *p++ * 0x100 + *p++;
        switch (type) {
            case 10: /** @brief supported_group */
                check_ext[0] = supported_group(p, len);
                break;
            case 11: /** @brief ec_point_format */
                check_ext[1] = point_format(p, len);
                break;
            case 51: /** @brief key_share */
                check_ext[2] = key_share(p, len);
                break;
            case 43: /** @brief supported_version */
                check_ext[3] = suppotred_version(p, len);
                break;
            case 45:                  /** @brief psk_exchange_modes */
                check_ext[4] = true;  // 항상 지원
                break;
        }
        p += len;
    }

    // Is possible TLS 1.3?
    for (int i = 0; i < 5; i++) {
        if (check_ext[i] == false) {
            return false;
        }
    }
}

template <bool SV>
bool TLS13::TLS13<SV>::supported_group(unsigned char *p, int len) {
    // secp256r1을 지원할 경우 true 0x0017
    for (int i = 2; i < len; i += 2) {
        if (*(p + i) == 0 && *(p + i + 1) == 0x17) {
            return true;
        }
    }
    return false;
}

template <bool SV>
bool TLS13::TLS13<SV>::point_format(unsigned char *p, int len) {
    for (int i = 1; i < len; i++) {
        if (*(p + i) == 0) {
            return true;
        }
    }
    return false;
}

template <bool SV>
bool TLS13::TLS13<SV>::sub_key_share(unsigned char *p) {
    if (*p == 0 && *(p + 1) == 23 && *(p + 4) == 4) {  // secp256r1 && legacy form
        AUTH::ECDSA::EC_Point Q{bnd_to_mpz(p + 5, p + 37) /**x[32]*/, bnd_to_mpz(p + 37, p + 69) /**y[32]*/, this->secp256r1_};
        premaster_secret_ = (Q * this->prv_key_).x; /** @remark TLS 1.3에서 key_share_extension을 통해 premaster_secret값을 설정한다!!*/
        return true;
    } else if (*p == 0 && *(p + 1) == 29) {  // x25519 0x001d
        uint8_t q[32];
        curve25519_mul(q, this->prv_, p + 4);//상대방의 공개키 * 자신의 개인키 ( premaster_secret )
        premaster_secret_ = bnd_to_mpz(q, q + 32); /** @remark TLS 1.3에서 key_share_extension을 통해 premaster_secret값을 설정한다!!*/
        this->P_.x = -1;                           /*** @remark if use x25519 => secp256r1은 사용하지 못한다.*/
        return true;
    } else
        return false;
}

template <bool SV>
bool TLS13::TLS13<SV>::key_share(unsigned char *p, int len) {
    for (unsigned char *q = p; p < q + len; p += p[2] * 0x100 + p[3] + 4 /*type + length*/) {
        if (sub_key_share(p)) {
            return true;
        }
    }
    return false;
}

template <bool SV>
bool TLS13::TLS13<SV>::suppotred_version(unsigned char *p, int len) {
    for (int i = 1; i < len; i += 2) {
        if (*(p + i) == 3 && *(p + i + 1) == 4) {  // TLS 1.3
            return true;
        }
    }
    return false;
}

template <bool SV>
string TLS13::TLS13<SV>::server_ext() {
    struct Ext {
        uint8_t extension_length[2] = {0, 79};  // total Length

        /**
         * @struct extension 1 : supported_version extension
         * @details 서버의 supported_version에서는 선택한거 딱 하나만 보내면됨(그러므로 길이 필드 필요없음)
         */
        uint8_t supported_version[2] = {0, 0x2b};     /** @brief extension type */
        uint8_t supported_version_length[2] = {0, 2}; /** @brief extension total length */
        uint8_t supported_versions[2] = {3, 4};       /** @brief TLS 1.3 */
    } ext;
    /**
     * @struct extension 2.1 : key_share_extension (secp256r1)
     */
    struct {
        uint8_t key_share[2] = {0, 51};             /** @brief extension type */
        uint8_t key_share_length[2] = {0, 69};     /** @brief extension total length*/

        uint8_t secp256r1_key[2] = {0, 23}; /** @brief algorithm type*/
        uint8_t key_length[2] = {0, 65};    /** @brief key length*/
        /**
         * @brief ECDHE Parameter */
        uint8_t type = 4;
        uint8_t x[32], y[32]; /** @brief key*/
    } secp;
    /**
     * @struct extension 2.2 : key_share_extension (x25519)
     */
    struct {
        uint8_t key_share[2] = {0, 51};             /** @brief extension type */
        uint8_t key_share_length[2] = {0, 36};     /** @brief extension total length*/
        uint8_t x25519[2] = {0, 29};      /** @brief algorithm type */
        uint8_t key_length2[2] = {0, 32}; /** @brief key length*/
        uint8_t x[32];                   /** @brief key */
    } x25519;
    if(this->P_.x == -1) { //client hello를 분석한후 선택한 스펙이 x25519인 경우
        curve25519_mul_g(x25519.x, this->prv_);//x25519.x = G * prv_
        ext.extension_length[1] = 46;//6 + 8 + 32
        return struct_to_str(ext) + struct_to_str(x25519);
    } else {//secp256r1
        mpz_to_bnd(this->P_.x, secp.x, secp.x + 32);
        mpz_to_bnd(this->P>.y, secp.y, secp.y + 32);
        return struct_to_str(ext) + struct_to_str(secp);
    }
}

template<bool SV>
bool TLS13::TLS13<SV>::server_ext(unsigned char *p) {
    int total_len = *p++ * 0x100 + *p++;
    for(unsigned char *q = p; p < q + total_len;) {
        int type = *p++ * 0x100 + *p++;
        int len = *p++ * 0x100 + *p++;
        //check the supported version extension..
        if(type == 51) /** @brief check key share extension */ {
            return key_share(p, len);
        }
        p += len;
    }
    return false;
}



#pragma pack()