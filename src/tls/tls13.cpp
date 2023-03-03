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
        this->aes_[i].key(&key[0]);              // set AES key
        this->aes_[i].iv(&iv[i], 0, iv.size());  // set AES iv

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
        uint8_t psk_mode[2] = {0, 0x2d};     /** @brief extension type */
        uint8_t psk_mode_length[2] = {0, 2}; /** @brief extension totla length*/
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
        uint8_t signature[6] = {8, 4, 4, 1, 4, 3};

    } ext;

    mpz_to_bnd(this->P_.x, ext.x, ext.x + 32);  // secp256r1 좌표 셋팅
    mpz_to_bnd(this->P_.y, ext.y, ext.y + 32);  // P_는 tls 1.2의 멤버
    mpz_to_bnd(sizeof(Ext) - 2 /*extension_length Field[2]*/, ext.extension_length, ext.extension_length + 2);

    mpz_to_bnd(this->prv_key_, prv_, prv_ + 32);  // prv_에 setting한다.
    curve25519_mul_g(ext.x2, prv_);               /** ext.x2 <= G(=9) * prv_ x25519 x좌표 셋팅 */
    return TLS::TLS<SV>::struct_to_str(ext);
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
    return true;
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
        curve25519_mul(q, this->prv_, p + 4);      // 상대방의 공개키 * 자신의 개인키 ( premaster_secret )
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
        uint8_t key_share[2] = {0, 51};        /** @brief extension type */
        uint8_t key_share_length[2] = {0, 69}; /** @brief extension total length*/

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
        uint8_t key_share[2] = {0, 51};        /** @brief extension type */
        uint8_t key_share_length[2] = {0, 36}; /** @brief extension total length*/
        uint8_t x25519[2] = {0, 29};           /** @brief algorithm type */
        uint8_t key_length2[2] = {0, 32};      /** @brief key length*/
        uint8_t x[32];                         /** @brief key */
    } x25519;
    if (this->P_.x == -1) {                      // client hello를 분석한후 선택한 스펙이 x25519인 경우
        curve25519_mul_g(x25519.x, this->prv_);  // x25519.x = G * prv_
        ext.extension_length[1] = 46;            // 6 + 8 + 32
        return TLS::TLS<SV>::struct_to_str(ext) + TLS::TLS<SV>::struct_to_str(x25519);
    } else {  // secp256r1
        mpz_to_bnd(this->P_.x, secp.x, secp.x + 32);
        mpz_to_bnd(this->P_.y, secp.y, secp.y + 32);
        return TLS::TLS<SV>::struct_to_str(ext) + TLS::TLS<SV>::struct_to_str(secp);
    }
}

template <bool SV>
bool TLS13::TLS13<SV>::server_ext(unsigned char *p) {
    int total_len = *p++ * 0x100 + *p++;
    for (unsigned char *q = p; p < q + total_len;) {
        int type = *p++ * 0x100 + *p++;
        int len = *p++ * 0x100 + *p++;
        // check the supported version extension..
        if (type == 51) /** @brief check key share extension */ {
            return key_share(p, len);
        }
        p += len;
    }
    return false;
}

template <bool SV>
string TLS13::TLS13<SV>::client_hello(string &&s) {
    if constexpr (SV) {                             // Server : client_hello 메시지 분석
        unsigned char *p = (unsigned char *)&s[43]; /**session_id length*/
        memcpy(echo_id_, p + 1, *p);                // copy session_id
        p += *p + 1;                                // p= cipher_suite length
        int cipher_suite_length = *p++ * 0x100 + *p++;
        p += cipher_suite_length;
        p += *p /*compression length*/ + 1 /*한칸뒤로 이동*/;  // extension start
        int ext_start = p - (unsigned char *)&s[0];
        /** @remark call TLS 1.2 Client Hello Function*/
        string r = TLS::TLS<SV>::client_hello(forward<string>(s));
        return s.size() > ext_start /* has extension */ && client_ext(p) /*is possible TLS 1.3*/ ? "" : r;
    } else {  // Client : client_hello 메시지 생성
        string hello = TLS::TLS<SV>::client_hello();
        this->accumulated_handshakes_ = "";
        string ext = client_ext();
        int hello_size = static_cast<uint8_t>(hello[3]) * 0x100 + static_cast<uint8_t>(hello[4]) + ext.size();
        mpz_to_bnd(hello_size, &hello[3], &hello[5]);      // length in tls header
        mpz_to_bnd(hello_size - 4, &hello[6], &hello[9]);  // length in handshake header
        return this->accumulate(hello + ext);
    }
}

template <bool SV>
string TLS13::TLS13<SV>::server_hello(string &&s) {
    if constexpr (SV) {  // Server : Server Hello 메시지 생성
        string tmp = this->accumulated_handshakes_;
        string hello = TLS::TLS<SV>::server_hello();
        if (!premaster_secret_) return hello;  // TLS1.2
        memcpy(&hello[44], echo_id_, 32);      // TLS 1.3에서는 클라이언트가 전송한 id를 저장후 에코한다.
        hello[76] = 19;
        hello[77] = 1;  // 암호화-해쉬 Cipher Suite : TLS AES128 GCM SHA 256TLS_AES_128_GCM_SHA256 = {0x13, 0x01}
        /** @remark 암호화 방법은 서버가 선택*/
        this->accumulated_handshakes_ = tmp;
        string ext = server_ext();
        int hello_size = static_cast<uint8_t>(hello[3]) * 0x100 + static_cast<uint8_t>(hello[4]) + ext.size();
        mpz_to_bnd(hello_size, &hello[3], &hello[5]);      // length in TLS Header
        mpz_to_bnd(hello_size - 4, &hello[6], &hello[9]);  // length in Handshake Header
        return this->accumulate(hello + ext);
    } else {  // Client : Server Hello 메시지 분석
        string s2 = s;
        string r = TLS::TLS<SV>::server_hello(move(s2));
        return s.size() > 80 /** 확장 데이터가 존재하는지 */ && server_ext((uint8_t *)&s[79]) /**server extension 메시지가 존재한다면 */ ? "" : r;
    }
}

template <bool SV>
string TLS13::TLS13<SV>::encrypted_extension() {
    /**
     * @struct encrypted extension
     */
    struct H {
        uint8_t enc_ext_type = 8;          /** @brief extension type*/
        uint8_t total_len[3] = {0, 0, 10}; /** @brief extension total length*/

        uint8_t ext_len[2] = {0, 8}; /** @brief start! extension length */
        /**
         * @struct extension 1 : key exchange supported_group extension
         */
        uint8_t supported_group[2] = {0, 10};            /** @brief extension type */
        uint8_t supported_group_list_length[2] = {0, 4}; /** @brief extension total length */
        uint8_t secp256r1[2] = {0, 23};                  /** @brief 0x0017 */
        uint8_t x255[2] = {0, 29};                       /** @brief 0x001d */
    } h;
    string r = TLS::TLS<SV>::struct_to_str(h);
    this->accumulated_handshakes_ += r;
    return r;
}

template <bool SV>
TLS13::TLS13<SV>::TLS13() {
    ifstream f2("../../ecdsa_key.pem");  // 비밀키 PEM 파일
    if (!f2.is_open()) {
        std::cerr << "ecdsa_key.pem open error" << std::endl;
    }
    ifstream f("../../ecdsa_cert.pem");  // 인증서 PEM 파일
    if (!f.is_open()) {
        std::cerr << "ecdsa_cert.pem open error" << std::endl;
    }
    // ECDSA
    DER::get_certificate_core(f2);
    auto jv = DER::pem_to_json(f2);
    cout << jv << endl;
    private_key = str_to_mpz(jv[0][1].asString());  // 비밀키 세팅

    std::vector<unsigned char> r;
    // 인코딩된 DER 값을 계속 읽는다.
    for (string s; (s = DER::get_certificate_core(f)) != "" /*더이상 인코딩된 DER이 존재하지 않을때*/;) {
        auto v = BASE64::base64_decode(s);  // v에는 인증서 vector
        // 인증서의 길이 공간 확보
        for (int i = 0; i < 3; i++) r.push_back(0);
        UTIL::mpz_to_bnd(v.size(), r.end() - 3, r.end());  // 인증서n의 크기
        r.insert(r.end(), v.begin(), v.end());             // 인증서n 삽입
    }
    // 길이1 DER1 길이2 DER2 0 0
    r.push_back(0);
    r.push_back(0);                 // ECDSA에서는 2바이트Padding을 넣어줘야함
    const int REQUEST_CONTEXT = 0;  // 1.3에서 추가된 필드

    vector<uint8_t> v = {TLS::HANDSHAKE /*TLS Content Type*/, /*TLS Version*/ 3, 3, /*TLS.length*/ 0, 0, /*Handshake Type*/ TLS::CERTIFICATE, /*HandShake.length*/ 0, 0, 0, /**TLS1.3버전 이후에 handshake header이후에 추가된 필드*/ REQUEST_CONTEXT, /*총 인증서 길이*/ 0, 0, 0};

    mpz_to_bnd(r.size(), v.end() - 3, v.end());                              // 총인증서의 길이
    mpz_to_bnd(r.size() + 4 /*REQUEST + 3*/, v.begin() + 6, v.begin() + 9);  // Length in Handshake Header
    mpz_to_bnd(r.size() + 8, v.begin() + 3, v.begin() + 5);                  // Length in TLS Header
    r.insert(r.begin(), v.begin(), v.end());                                 // header 삽입
    this->ecdsa_certificate_.assign(r.begin(), r.end());                     // 인증서 설정
}

template <bool SV>
string TLS13::TLS13<SV>::certificate_verify() {
    HASH::SHA2 sha;  // hash accmulated handshakes
    auto a = sha.hash(this->accumulated_handshakes_.begin(), this->accumulated_handshakes_.end());
    string t;
    for (int i = 0; i < 64; i++) {  // 0x20을 64바이트 만큼 채운다.
        t += ' ';
    }
    t += "TLS 1.3, server CertificateVerify";
    t += (uint8_t)0x0;
    t.insert(t.end(), a.begin(), a.end());  // 0x20... TLS 1.3, server CertificateVerify0hash
    // t is 서명할 자료구조
    a = sha.hash(t.begin(), t.end());

    /**
     * @struct certificate verify message
     */
    struct {
        uint8_t type = 0x0f;                /** @brief certificate verify */
        uint8_t length[3] = {0, 0, 74};     /** @brief length*/
        uint8_t signature[2] = {4, 3};      /** @brief signature algorithm ecdsa_secp256r1_sha256(0x0403),*/
        uint8_t len[2] = {0, 70};           /** @brief signature length*/
        uint8_t der[4] = {0x30, 68, 2, 32}; /** @brief signature : r, s */
        /** 0x30 : 복합 시퀀스*/
        /** 68 : 전체 인증서 길이*/
        /** 2, 32 : DER1 */

        /** 2: Integer */
        /** 32 : R length*/
    } cert_verify_struct;
    vector<uint8_t> R(32), S(32);  // ECDSA r, s
    /** 2: Integer */
    /** 32 : S length*/
    uint8_t der2[2] = {2, 32};

    AUTH::ECDSA ecdsa{this->G_, 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_mpz /*차수*/};

    auto [r, s] = ecdsa.sign(bnd_to_mpz(a.begin(), a.end()), private_key);  // private_key로 서명
    mpz_to_bnd(r, R.begin(), R.end());
    mpz_to_bnd(s, S.begin(), S.end());
    if (R[0] >= 0x80) {                  // 서명쌍 생성 -> DER 방식의 정수로 변환할 경우 첫번째 바이트의 첫비트는 음수를 표현 한다.따라서 첫 비트가 1로 세팅되어있다면 00패딩
        cert_verify_struct.length[2]++;  // 전체 길이 증가
        cert_verify_struct.len[1]++;     // signature length 증가
        cert_verify_struct.der[1]++;     // 전체 인증서 길이 증가
        cert_verify_struct.der[3]++;     // R length 증가
        R.insert(R.begin(), 0);          // 첫번째 바이트에 0삽입
    }
    if (S[0] >= 0x80) {                  // 서명쌍 생성 -> DER 방식의 정수로 변환할 경우 첫번째 바이트의 첫비트는 음수를 표현 한다.따라서 첫 비트가 1로 세팅되어있다면 00패딩
        cert_verify_struct.length[2]++;  // 전체 길이 증가
        cert_verify_struct.len[1]++;     // signature length 증가
        cert_verify_struct.der[1]++;     // 전체 인증서 길이 증가
        der2[1]++;                       // S length 증가
        S.insert(S.begin(), 0);          // 첫번째 바이트에 0삽입
    }
    t = TLS::TLS<SV>::struct_to_str(cert_verify_struct) + string{R.begin(), R.end()} + string{der2, der2 + 2} + string{S.begin(), S.end()};
    this->accumulated_handshakes_ += t;
    return t;
}

template <bool SV>
string TLS13::TLS13<SV>::finished(string &&s) {
    // 이 함수는 TLS Header를 포함하지않는다.
    struct H {
        uint8_t finished = 0x14;
        uint8_t length[3] = {0, 0, 32};
    } h;
    /**
     * @remark finished_key = salt(handshake_traffic_secret), expand_label("finished","",hashsize)
     */
    hkdf_.salt(finished_key_[s == "" ? SV /*finished 메시지 생성 : Server*/ : !SV /*finished 메시지 분석 : Client*/].data(), HASH::SHA2::output_size);
    HASH::SHA2 sha;  // Cipher Suite에서 정한 알고리즘
    /**
     * @remark HMAC(finished_key, Hash(acc))
     */
    auto a = sha.hash(this->accumulated_handshakes_.begin(), this->accumulated_handshakes_.end());
    a = hkdf_.hash(a.begin(), a.end());
    string fin = TLS::TLS<SV>::struct_to_str(h) + string{a.begin(), a.end()};
    this->accumulated_handshakes_ += fin;
    if (s == "")
        return fin;  // finished message 생성
    else
        return s == fin /*finished message 분석*/ ? "" /*정상*/ : this->alert(2, 51) /*오류*/;
}

template <bool SV>
string TLS13::TLS13<SV>::encode(string &&s, int type) {
    return premaster_secret_ ? encode13(forward<string>(s), type) : TLS::TLS<SV>::encode(forward<string>(s), type);
}

template <bool SV>
optional<string> TLS13::TLS13<SV>::decode(string &&s) {
    return premaster_secret_ ? decode13(forward<string>(s)) : TLS::TLS<SV>::decode(forward<string>(s));
}

template <bool SV>
string TLS13::TLS13<SV>::encode13(string &&s, int type) {
    uint8_t seq[8];
    TLS::TLS_header h1;
    h1.content_type = 23;  // Applicaton Data

    mpz_to_bnd(this->enc_seq_num_++, seq, seq + 8);        // set sequence number
    const size_t chunk_size = (1 << 14) - 64;              // 패킷당 최대 허용크기
    string frag = s.substr(0, chunk_size) + string{type};  // type padding
    h1.set_length(frag.size() + 16 /*인증 태그 길이*/);

    uint8_t *p = (uint8_t *)&h1;
    this->aes_[SV].aad(p, 5);  // set additional auth data
    p = (uint8_t *)frag.data();
    this->aes_[SV].xor_with_iv(seq);                    // iv 값과 seq앞에 4바이트 padding한값 xor
    auto tag = this->aes_[SV].encrypt(p, frag.size());  // 16byte의 인증태그
    this->aes_[SV].xor_with_iv(seq);                    // iv값을 원상복구 시킨다.
    frag += string{tag.begin(), tag.end()};
    string s2 = TLS::TLS<SV>::struct_to_str(h1) + frag;
    if (s.size() > chunk_size) s2 += encode(s.substr(chunk_size));
    return s2;
}

template <bool SV>
optional<string> TLS13::TLS13<SV>::decode13(string &&s) {
    struct H {
        TLS::TLS_header h1;
        unsigned char encrypted_msg[];
    } *p = (H *)s.data();
    uint8_t seq[8];

    if (int type = this->get_content_type(s).first; type != TLS::APPLICATION_DATA) {
        this->alert(this->alert(2, 10));
        return {};
    }

    mpz_to_bnd(this->dec_seq_num_++, seq, seq + 8);
    int msg_len = p->h1.get_length() - 16 /*tag Length*/;

    this->aes_[!SV].aad((uint8_t *)p, 5);                               // 상대방의 정보를 set Additional Auth Data
    this->aes_[!SV].xor_with_iv(seq);                                   // 상대방의 정보를 set IV
    auto auth = this->aes_[!SV].encrypt(p->encrypted_msg, msg_len);    // 인증 태그를 얻고 복호화한다.
    this->aes_[!SV].xor_with_iv(seq);                                   // IV를 원상 복구 한다.
    if (equal(auth.begin(), auth.end(), p->encrypted_msg + msg_len)) {  // 생성한 인증태그와 수신한 인증태그를 비교한다.
        string r{p->encrypted_msg, p->encrypted_msg + msg_len};         // 복호화된 메시지
        while (r.back() == 0) r.pop_back();                             // padding 제거
        if (r.back() == TLS::ALERT) {                                   // type
            this->alert(this->alert(r[0] /*alert level*/, r[1] /*alert desc*/));
            return {};
        }
        r.pop_back();  // remove type
        return r;      // 복호화된 메시지
    } else {
        this->alert(this->alert(2, 20));
        return {};
    }
}

template <bool SV>
bool TLS13::TLS13<SV>::handshake(std::function<std::optional<std::string>()> read_f,
                                 std::function<void(std::string)> write_f) {
    string s;
    optional<string> a;
    switch (1) {
        case 1:                  // break로 간편하게 handshake중단 가능
            if constexpr (SV) {  // Server
                if (s = this->alert(2, 0);
                    !(a = read_f()) /*Client Hello : 성공적으로 읽었다면*/ || (s = client_hello(move(*a))) != "" /*client_hello도 성공적으로 수행했다면*/) break;
                if (s = this->server_hello(); premaster_secret_) {  // if TLS 1.3 && Server Hello Message 생성
                    protect_handshake();                            // Set HandShake Traffic Secret
                    s += this->change_cipher_spec();
                    string t = encrypted_extension();
                    t += server_certificate13();
                    t += certificate_verify();
                    t += finished();
                    // Handshake traffic secret으로 암호화!
                    s += this->encode(move(t), TLS::HANDSHAKE);
                    write_f(s);  // 전송
                    if (s = this->alert(2, 0); !(a = read_f()) /*cient change_cipher_spec 성공적으로 읽었다면*/ ||
                                               (s = this->change_cipher_spec(move(*a))) != "" /*change_cipher_spec도 성공적으로 수행 했다면*/) break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               !(a = this->decode(move(*a))) /*암호화된 finished 복호화*/ || (protect_data(), false) /*set Application Traffic Secret*/ || (s = finished(move(*a))) != "" /*성공적으로 finished 분석*/) break;
                } else {  // TLS 1.2
                    s += this->server_certificate();
                    s += this->server_key_exchange();
                    s += this->server_hello_done();
                    write_f(s);  // 전송
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->client_key_exchange(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->change_cipher_spec(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = TLS::TLS<SV>::finished(move(*a))) != "") break;
                    s = this->change_cipher_spec();
                    s += TLS::TLS<SV>::finished();
                    write_f(move(s));
                }
            } else {                      // Client
                write_f(client_hello());  // send client_hello message
                if (a = read_f(); !a || (s = server_hello(move(*a))) != "") break;
                if (premaster_secret_) {  // if TLS 1.3
                    protect_handshake();  // set handshake traffic secret
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->change_cipher_spec(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) || !(a = this->decode(move(*a))))
                        break;
                    else
                        this->accumulated_handshakes_ += *a; /*a는 복호화된 encrypted_extension + server_certificate13 + certificate_verify + finished*/
                    /**
                     * @todo server의 인증서를 확인하는 알고리즘!!
                     */
                    string tmp = this->accumulated_handshakes_;
                    s = this->change_cipher_spec();
                    s += this->encode(finished());  // change_cipher_spec + finished message encode
                    write_f(move(s));
                    this->accumulated_handshakes_ = tmp;
                    protect_data();
                } else {
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->server_certificate(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->server_key_exchange(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->server_hello_done(move(*a))) != "") break;
                    s = this->client_key_exchange();
                    s += this->change_cipher_spec();
                    s += TLS::TLS<SV>::finished();
                    write_f(move(s));  // empty s
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = this->change_cipher_spec(move(*a))) != "") break;
                    if (s = this->alert(2, 0); !(a = read_f()) ||
                                               (s = TLS::TLS<SV>::finished(move(*a))) != "") break;
                }
            }
    }

    if (s != "") {   // break로 중간에 HandShaking을 중단한 경우
        write_f(s);  // send alert message
        return false;
    } else
        return true;
}

#pragma pack()