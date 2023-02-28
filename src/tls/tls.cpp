#include "tls.h"
#pragma pack(1)

using namespace std;

template class TLS::TLS<true>;   // server
template class TLS::TLS<false>;  // client

template <bool SV>
std::string TLS::TLS<SV>::alert(uint8_t level, uint8_t desc) {
// 암호화 하여 전송할때에는 아래와 같이 호출
// send(encode(alert(2, 20).substr(sizeof(TLS_header)), 0x15));
    struct {
        TLS_header h1;
        uint8_t alert_level;
        uint8_t alert_desc;
    } h;
    h.h1.content_type = 0x15;  // ALERT_MESSAGE
    h.alert_level = level;
    h.alert_desc = desc;
    h.h1.set_length(2);
    return struct_to_str(h);
}

template <bool SV>
int TLS::TLS<SV>::alert(string &&s) {
    struct H {
        TLS_header h1;
        uint8_t alert_level;
        uint8_t alert_desc;
    } *p = (H *)s.data();
    int level, desc;
    // alert 메시지는 암호화 되어 있을 수도 있음
    if (p->h1.get_length() == 2) {  // 암호화 되지 않음
        level = p->alert_level;
        desc = p->alert_desc;
    } else {  // 암호화된 alert 메시지인 경우
        s = *decode(move(s));
        // 오류 처리 해야함
        // if (s.has_value() == false) {
        //    std::cerr << "alert 메시지 복호화 오류" << std::endl;
        //} else {
        level = static_cast<uint8_t>(s[0]);
        desc = static_cast<uint8_t>(s[1]);
        //}
    }
    switch (desc) {  // s reuse
        case 0:
            s = "close_notify(0)";
            break;
        case 10:
            s = "unexpected_message(10)";
            break;
        case 20:
            s = "bad_record_mac(20)";
            break;
        case 21:
            s = "decryption_failed_RESERVED(21)";
            break;
        case 22:
            s = "record_overflow(22)";
            break;
        case 30:
            s = "decompression_failure(30)";
            break;
        case 40:
            s = "handshake_failure(40)";
            break;
        case 41:
            s = "no_certificate_RESERVED(41)";
            break;
        case 42:
            s = "bad_certificate(42)";
            break;
        case 43:
            s = "unsupported_certificate(43)";
            break;
        case 44:
            s = "certificate_revoked(44)";
            break;
        case 45:
            s = "certificate_expired(45)";
            break;
        case 46:
            s = "certificate_unknown(46)";
            break;
        case 47:
            s = "illegal_parameter(47)";
            break;
        case 48:
            s = "unknown_ca(48)";
            break;
        case 49:
            s = "access_denied(49)";
            break;
        case 50:
            s = "decode_error(50)";
            break;
        case 51:
            s = "decrypt_error(51)";
            break;
        case 60:
            s = "export_restriction_RESERVED(60)";
            break;
        case 70:
            s = "protocol_version(70)";
            break;
        case 71:
            s = "insufficient_security(71)";
            break;
        case 80:
            s = "internal_error(80)";
            break;
        case 90:
            s = "user_canceled(90)";
            break;
        case 100:
            s = "no_renegotiation(100)";
            break;
        case 110:
            s = "unsupported_extension(110)";
            break;
    }
    if (level == 1)
        std::cerr << s << endl;
    else if (level == 2)
        std::cerr << s << endl;
    return desc;
}

template <bool SV>
string TLS::TLS<SV>::client_hello(string &&s) {
    struct H {
        TLS_header h1;
        HandShake_header h2;
        Hello_header h3;
        uint8_t cipher_suite_length[2] = {0, 2};  // 총2byte로 구성 되어 있다.
        // 모든 Cipher Suite값은 2바이트로 구성되어 있으므로 1개의 Cipher Suite 존재
        uint8_t cipher_suite[2] = {0xc0, 0x2f};  // ECDHE_RSA_AES128_GCM_SHA256
        uint8_t compression_length = 1;
        uint8_t compression_method = 0;  // none
    } r;
    if constexpr (!SV) {  // Client -> Client Hello 메시지 생성
        r.h2.handshake_type = CLIENT_HELLO;
        r.h1.set_length(sizeof(r) - sizeof(TLS_header));
        r.h2.set_length(sizeof(r) - sizeof(TLS_header) - sizeof(HandShake_header));
        UTIL::mpz_to_bnd(UTIL::random_prime(32), r.h3.random, r.h3.random + 32);  // 클라이언트에 Client Random
        memcpy(client_random_.data(), r.h3.random, 32);                           // TLS 클래스에 Client Random 값 저장
        return accumulate(struct_to_str(r));
    } else {  // Server -> Client Hello 메시지 분석
        if (get_content_type(s) != pair{HANDSHAKE /*tls header content type*/, CLIENT_HELLO /*handshake header type*/}) {
            return alert(2, 10);  // fatal, unexpected message
        }
        accumulate(s);
        H *p = (H *)s.data();
        memcpy(client_random_.data(), p->h3.random, 32);  // 서버에 Client Random값 저장
        unsigned char *q = &p->h3.session_id_length;
        q += *q + 1;                                        // q ->cipher_suite_length
        int client_cipher_suite_len = *q++ * 0x100 + *q++;  // calc Client Cipher Suite Length

        // 클라이언트가 가능한 Cipher Suite와 서버가 제공하는 Cipher Suite 확인 및 비교
        for (int i = 0; i < client_cipher_suite_len; i += 2 /*Cipher Suite의 크기*/) {
            if (*(q + i) == 0xc0 && *(q + i + 1) == 0x2f) {  // Cipher Suite 값이 0xc0, 0x2f 라면 Client Hello 성공!
                return "";
            }
        }
        return alert(2, 40);  // fatal, handshake failure
    }
}

template <bool SV>
string TLS::TLS<SV>::accumulate(const string &s) {
    accumulated_handshakes_ += s.substr(sizeof(TLS_header));  // Length만큼 짜른다.
    return s;
}

template <bool SV>
string TLS::TLS<SV>::server_hello(string &&s) {
    struct H {
        TLS_header h1;
        HandShake_header h2;
        Hello_header h3;
        // 모든 Cipher Suite값은 2바이트로 구성되어 있으므로 1개의 Cipher Suite 존재
        uint8_t cipher_suite[2] = {0xc0, 0x2f};  // ECDHE_RSA_AES128_GCM_SHA256
        uint8_t compression_method = 0;          // none
    } r;
    if constexpr (SV) {  // Server -> server Hello Message 생성
        // r.h1.length[1] = sizeof(Hello_header) + sizeof(HandShake_header) + 3/*Cipher Suite[2] + compression_method[1]*/;
        // 왜 set length안쓰지
        r.h1.set_length(sizeof(Hello_header) + sizeof(HandShake_header) + 3);
        r.h2.set_length(sizeof(Hello_header) + 3);
        r.h2.handshake_type = SERVER_HELLO;
        UTIL::mpz_to_bnd(UTIL::random_prime(32), server_random_.begin(), server_random_.end());  // Server Random
        memcpy(r.h3.random, server_random_.data(), 32);
        UTIL::mpz_to_bnd(UTIL::random_prime(32), session_id_.begin(), session_id_.end());  // Server 는 Session Generate함
        memcpy(r.h3.session_id, session_id_.data(), 32);
        return accumulate(struct_to_str(r));
    } else {  // Client -> Server Hello Message 분석
        if (get_content_type(s) != pair{HANDSHAKE, SERVER_HELLO}) {
            return alert(2, 10);  // fatal, unexpected message
        }
        accumulate(s);
        H *p = (H *)s.data();
        memcpy(server_random_.data(), p->h3.random, 32);   // Client TLS 클래스에 server random data 저장
        memcpy(session_id_.data(), p->h3.session_id, 32);  // Client TLS 클래스에 session_id 저장
        if (p->cipher_suite[0] == 0xc0 && p->cipher_suite[1] == 0x2f)
            return "";
        else
            return alert(2, 40);  // fatal, handshake failure
    }
}

template <bool SV>
TLS::TLS<SV>::TLS() {
    if constexpr (SV) {          // Server
        ifstream f2("../../key.pem");  // 비밀키 PEM 파일
        if(!f2.is_open()) {
            std::cerr << "key.pem open error" << std::endl;
        }
        ifstream f("../../cert.pem");  // 인증서 PEM 파일
        if(!f.is_open()) {
            std::cerr << "cert.pem open error" << std::endl;
        }
        auto [K, e, d] = DER::get_keys(f2);
        this->rsa_.set_key(e, d, K);
        std::vector<unsigned char> r;
        // 인코딩된 DER 값을 계속 읽는다.
        for (string s; (s = DER::get_certificate_core(f)) != "" /*더이상 인코딩된 DER이 존재하지 않을때*/;) {
            auto v = BASE64::base64_decode(s);  // v에는 인증서 vector
            // 인증서의 길이 공간 확보
            for (int i = 0; i < 3; i++) r.push_back(0);
            UTIL::mpz_to_bnd(v.size(), r.end() - 3, r.end());  // 인증서n의 크기
            r.insert(r.end(), v.begin(), v.end());             // 인증서n 삽입
        }
        vector<uint8_t> v = {HANDSHAKE /*TLS Content Type*/, /*TLS Version*/ 3, 3, /*TLS.length*/ 0, 0, /*Handshake Type*/ CERTIFICATE, /*HandShake.length*/ 0, 0, 0, /*총 인증서 길이*/ 0, 0, 0};
        UTIL::mpz_to_bnd(r.size(), v.end() - 3, v.end());                                                          // 전체 인증서 길이 삽입
        UTIL::mpz_to_bnd(r.size() + 3 /*총 인증서 길이[3]*/, v.end() - 6, v.end() - 3);                            // HandShake Header Length 값
        UTIL::mpz_to_bnd(r.size() + 7 /*총 인증서 길이[3] + HandShake Header[4]*/, v.begin() + 3, v.begin() + 5);  // TLS Header Length 값
        r.insert(r.begin(), v.begin(), v.end());                                                                   // TLS Header + HandShake Header + Total Cert Length + Cert1_length + Cert[] + ...
        // this->certificate_{r.begin(), r.end()};
        this->certificate_.assign(r.begin(), r.end());
    }
}

template <bool SV>
string TLS::TLS<SV>::server_certificate(string &&s) {
    if constexpr (SV)
        return accumulate(certificate_);  // 서버라면 이미 생성한 Certificate 메시지 리턴 및 누적
    else {                                // 클라이언트라면 DER로 전송 받은 인증서 Parsing
        if (get_content_type(s) != pair{HANDSHAKE, CERTIFICATE}) {
            return alert(2, 10);
        }
        /**
         * @todo 인증서 체인이 있는지 확인후, 다음 인증서의 공개키와 서명을 얻고, 다음 인증서의 공개키로 첫번째 인증서의 서명을 확인한다.
         */
        accumulate(s);
        struct H {
            TLS_header h1;
            HandShake_header h2;
            uint8_t certificate_length[2][3];  // 전체인증서 길이, 인증서 1의길이
            unsigned char certificate[];       // 첫번째 인증서
        } *p = (H *)s.data();
        stringstream ss;
        uint8_t *q = p->certificate_length[1];                                         // 인증서1의 길이
        for (int i = 0, j = *q * 0x10000 + *(q + 1) * 0x100 + *(q + 2); i < j; i++) {  // 인증서1을 ss에 저장
            ss << noskipws << p->certificate[i];
        }
        Json::Value jv;
        try {  // DER을 Parsing하는 과정에서 예외가 발생 할 수 있다.
            jv = DER::der_to_json(ss);
        } catch (const char *e) {
            cerr << "certificate error : " << e << '\n';
            return alert(2, 44);  // fatal, certificate revoked
        }
        auto [K, e, sign] = DER::get_pubkeys(jv);
        rsa_.K = K;  // 공개키 저장
        rsa_.e = e;
        return "";
    }
}

template <bool SV>
void TLS::TLS<SV>::generate_signature(unsigned char *pub_key /** named curve,secp... x, y*/, unsigned char *sign /*서명할 위치*/) {
    unsigned char a[64 /*client random, server random*/ + 69 /*named curve, secp, ..., x, y*/];  // 해쉬할 자료구조
    memcpy(a, client_random_.data(), 32);
    memcpy(a + 32, server_random_.data(), 32);
    memcpy(a + 64, pub_key, 69);
    HASH::SHA2 sha;
    auto b = sha.hash(a, a + 64 + 69);
    std::deque<unsigned char> dq{b.begin(), b.end()};
    dq.push_front(dq.size());  // 해쉬값의 길이 H
    // padding
    unsigned char der_bytes[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04};
    dq.insert(dq.begin(), der_bytes, der_bytes + 16);  // DER bytes 삽입
    dq.push_front(dq.size());                          // 이후 데이터의 총길이
    dq.push_front(0x30);
    dq.push_front(0x00);
    while (dq.size() < 254) dq.push_front(0xff);
    dq.push_front(0x01);
    dq.push_front(0x00);
    auto z = rsa_.sign(UTIL::bnd_to_mpz(dq.begin(), dq.end()));
    UTIL::mpz_to_bnd(z, sign, sign + 256);  // 서명 저장
}

template <bool SV>
void TLS::TLS<SV>::derive_keys(mpz_class premaster_secret) {
    unsigned char pre[32], rand[64];
    UTIL::mpz_to_bnd(premaster_secret, pre, pre + 32);
    HASH::PRF<HASH::SHA2> prf;  // Pseudo random function
    prf.secret(pre, pre + 32);
    memcpy(rand, client_random_.data(), 32);
    memcpy(rand + 32, server_random_.data(), 32);
    prf.seed(rand, rand + 64);  // set seed
    prf.label("master secret");
    master_secret_ = prf.expand_n_byte(48);
    prf.secret(master_secret_.begin(), master_secret_.end());
    memcpy(rand, server_random_.data(), 32);
    memcpy(rand + 32, client_random_.data(), 32);
    prf.seed(rand, rand + 64);  // set seed
    prf.label("key expansion");
    auto v = prf.expand_n_byte(40);
    aes_[0].key(&v[0]);        // Client AES KEy
    aes_[1].key(&v[16]);       // Server AES Key
    aes_[0].iv(&v[32], 0, 4);  // client salt, Client IV의 앞부분
    aes_[1].iv(&v[36], 0, 4);  // server salt, Server IV의 앞부분
}

template <bool SV>
string TLS::TLS<SV>::server_key_exchange(string &&s) {
    struct H {
        TLS_header h1;
        HandShake_header h2;
        uint8_t named_curve = 3,
                secp256r[2] = {0, 0x17},
                key_length = 65,
                uncompressed = 4,
                x[32], y[32];
        uint8_t signature_hash = 4,       /**SHA256 */
            signature_sign = 1,           /**rsa*/
            signature_length[2] = {1, 0}, /**256 bytes*/
            sign[256];
    } r;

    if constexpr (SV) {  // Server -> 메시지 생성
        r.h1.set_length(sizeof(r) - sizeof(TLS_header));
        r.h2.set_length(sizeof(r) - sizeof(TLS_header) - sizeof(HandShake_header));
        r.h2.handshake_type = SERVER_KEY_EXCHANGE;
        UTIL::mpz_to_bnd(P_.x, r.x, r.x + 32);  // Server 의 공개키좌표를 입력한다.
        UTIL::mpz_to_bnd(P_.y, r.y, r.y + 32);
        generate_signature(&r.named_curve, r.sign);  // 서명을 생성 및 이어 붙힌다.
        return accumulate(struct_to_str(r));
    } else {  // Client -> 메시지 분석
        if (get_content_type(s) != pair{HANDSHAKE, SERVER_KEY_EXCHANGE}) {
            return alert(2, 10);  // fatal, unexpected message
        }
        accumulate(s);
        const H *p = reinterpret_cast<const H *>(s.data());
        // 받은 메시지에서 서버의 공개키를 저장한다.
        AUTH::ECDSA::EC_Point Y{UTIL::bnd_to_mpz(p->x, p->x + 32), UTIL::bnd_to_mpz(p->y, p->y + 32), secp256r1_};
        // 서버의 공개키 정보 * 클라이언트의 비밀키 의 x좌표(premaster_secret)를 이용해 키를 확장한다.
        derive_keys((Y * prv_key_).x);

        // x, y좌표의 변조를 서명을 통해 확인한다.
        auto z = rsa_.encode(UTIL::bnd_to_mpz(p->sign, p->sign + 256));
        UTIL::mpz_to_bnd(z, r.sign, r.sign + 256);  // 서명 해제한것을 r에 저장한다. -> 총 256바이트 0, 1, padding, 0, 48, S, DER Bytes, SHA256
        memcpy(r.sign, client_random_.data(), 32);  //
        memcpy(r.sign + 32, server_random_.data(), 32);
        memcpy(r.sign + 64, &p->named_curve, 69);
        HASH::SHA2 sha;
        auto a = sha.hash(r.sign, r.sign + 64 + 69);
        // 클라이언트가 구한 x좌표,y좌표 해쉬값과 건네받은 해쉬값 비교
        if (equal(r.sign + 224, r.sign + 256, a.begin()))
            return "";
        else
            return alert(2, 51);  // fatal, decrypt error
    }
}

template <bool SV>
string TLS::TLS<SV>::server_hello_done(string &&s) {
    struct {
        TLS_header h1;
        HandShake_header h2;
    } r;
    if constexpr (SV) {  // 서버라면 메시지 생성
        r.h2.handshake_type = SERVER_DONE;
        return accumulate(struct_to_str(r));
    } else {  // 클라이언트라면 메시지 Pasring 및 분석
        if (get_content_type(s) != pair{HANDSHAKE, SERVER_DONE}) {
            return alert(2, 10);  // fatal, unexpected message
        }
        accumulate(s);
        return "";
    }
}

template <bool SV>
string TLS::TLS<SV>::client_key_exchange(string &&s) {
    struct H {
        TLS_header h1;
        HandShake_header h2;
        uint8_t len = 65;
        uint8_t uncommpressed = 4;
        uint8_t x[32], y[32];
    } r;
    if constexpr (SV) {  // 서버 -> 메시지 분석
        if (get_content_type(s) != pair{HANDSHAKE, CLIENT_KEY_EXCHANGE}) {
            return alert(2, 10);
        }
        accumulate(s);
        H *p = (H *)s.data();
        AUTH::ECDSA::EC_Point Y{UTIL::bnd_to_mpz(p->x, p->x + 32), UTIL::bnd_to_mpz(p->y, p->y + 32), secp256r1_};
        derive_keys((Y * prv_key_).x);  // 클라이언트와 값이 똑같을것이다. Y * prv_key의 좌표는 같기 때문에
        return "";
    } else {  // 클라이언트에서는 자신의 공개키 전송
        r.h2.handshake_type = 16;
        r.h1.set_length(sizeof(H) - sizeof(TLS_header));
        r.h2.set_length(sizeof(H) - sizeof(TLS_header) - sizeof(HandShake_header));
        UTIL::mpz_to_bnd(P_.x, r.x, r.x + 32);  // 클라이언트의 공개키값을 저장한다.
        UTIL::mpz_to_bnd(P_.y, r.y, r.y + 32);
        return accumulate(struct_to_str(r));
    }
}

template <bool SV>
string TLS::TLS<SV>::change_cipher_spec(string &&s) {
    struct {
        TLS_header h1;
        uint8_t spec = 1;
    } r;
    r.h1.content_type = CHANGE_CIPHER_SPEC;
    r.h1.set_length(1);
    return s == "" ?
                   /*송신이라면*/ struct_to_str(r)
                   :
                   /*수신이라면*/ (get_content_type(s).first /*TLS.content_type*/ == CHANGE_CIPHER_SPEC ? ""
                                                                                                        : alert(2, 10));
}

template <bool SV>
optional<string> TLS::TLS<SV>::decode(string &&s) {
    /**
     * 레코드 메시지의 구조
     */
    struct H {
        TLS_header h1;
        uint8_t iv[8];
        unsigned char m[];
    } *p = (H *)s.data();
    /**
     * 인증 태그를 위한 부가정보
     */
    struct {
        uint8_t seq[8];
        TLS_header h1;
    } header_for_mac;

    if (int type = get_content_type(s).first; type != HANDSHAKE && type != APPLICATION_DATA)
        return {};                                                                 // error
    UTIL::mpz_to_bnd(dec_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);  // 순서 번호를 넣고 증가시킨다.
    header_for_mac.h1 = p->h1;
    int msg_len = p->h1.get_length() - sizeof(H::iv) - 16 /*tag length*/;
    header_for_mac.h1.set_length(msg_len);
    uint8_t *aad = (uint8_t *)&header_for_mac;
    // 상대쪽 정보로 복호화
    aes_[!SV].aad(aad, sizeof(header_for_mac));
    aes_[!SV].iv(p->iv, 4, 8);  // IV값의 뒷부부은 salt값으로 이미 저장됨
    auto auth = aes_[!SV].decrypt(p->m, msg_len);
    // 인증 태그 확인
    if (equal(auth.begin(), auth.end(), p->m + msg_len)) {
        return string{p->m, p->m + msg_len};
    } else {
        return {};  // 인증태그 확인 실패
    }
}

template <bool SV>
string TLS::TLS<SV>::encode(string &&s, int type) {
    /**
     * 레코드 메시지 구조
     */
    struct {
        TLS_header h1;
        uint8_t iv[8];
    } header_to_send;
    /**
     * 인증 태그를 위한 부가정보
     */
    struct {
        uint8_t seq[8];
        TLS_header h1;
    } header_for_mac;
    header_for_mac.h1.content_type = header_to_send.h1.content_type = type;

    UTIL::mpz_to_bnd(enc_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);
    const size_t chunk_size = (1 << 14) - 64;  // 하나의 패킷에 허용할 최대 길이
    int len = min(s.size(), chunk_size);
    header_for_mac.h1.set_length(len);
    string frag = s.substr(0, len);  // 문자 잘라버림

    UTIL::mpz_to_bnd(UTIL::random_prime(8), header_to_send.iv, header_to_send.iv + 8);  // IV값 랜덤 생성
    aes_[SV].iv(header_to_send.iv, 4, 8);
    uint8_t *aad = (uint8_t *)&header_for_mac;
    aes_[SV].aad(aad, sizeof(header_for_mac));
    auto tag = aes_[SV].encrypt(reinterpret_cast<unsigned char *>(&frag[0]), frag.size());  // 잘라낸 부분만 암호화
    frag += string(tag.begin(), tag.end());                                                 // 인증 태그 첨부
    header_to_send.h1.set_length(sizeof(header_to_send.iv) + frag.size());

    string s2 = struct_to_str(header_to_send) + frag /*암호 + 인증 태그*/;
    // chunk_size만큼 앞부분 잘라내고 뒷부분 다시 암호화(이렇게 생긴 결과값은 TLS Header와 AES IV, 암호메시지, 인증태그 모두를 포함한다.
    if (s.size() > chunk_size) s2 += encode(s.substr(chunk_size));
    return s2;
}

template <bool SV>
string TLS::TLS<SV>::finished(string &&s) {
    HASH::PRF<HASH::SHA2> prf;
    HASH::SHA2 sha;
    prf.secret(master_secret_.begin(), master_secret_.end());
    auto h = sha.hash(accumulated_handshakes_.cbegin(), accumulated_handshakes_.cend());
    prf.seed(h.begin(), h.end());
    const char *label[2] = {"client finished", "server finished"};
    prf.label(label[s == "" ? SV : !SV]);
    auto v = prf.expand_n_byte(12);
    std::cout << "finished" << std::endl;
    std::cout << "accumulate PRF : ";
    for (const auto &c : v) {
        std::cout << std::hex << static_cast<int>(c);
    }
    std::cout << '\n';

    HandShake_header hh;
    hh.handshake_type = FINISHED;
    hh.set_length(12);

    string msg = struct_to_str(hh) + string{v.begin(), v.end()};
    accumulated_handshakes_ += msg;

    if (s == "")
        return encode(move(msg), HANDSHAKE);  // 메시지를 보내는 경우
    else if (decode(move(s)) != msg)
        return alert(2, 51);  // 메시지를 받는경우
    else
        return "";
}

template <bool SV>
pair<int, int> TLS::TLS<SV>::get_content_type(const string &s) {
    uint8_t *p = (uint8_t *)s.data();
    return {p[0], p[5]};
}

#pragma pack()