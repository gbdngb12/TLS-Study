#include "tls13.h"
using namespace std;
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
    array<vector<unsigned char>, 2> secret/**traffic secret*/, finished_key/**handshake 에서 사용하는 finished key*/;
    secret[0] = hkdf_.derive_secret(client_label, this->accumulated_handshakes_);//traffic secret
    secret[1] = hkdf_.derive_secret(server_label, this->accumulated_handshakes_);//traffic secret
    for(int i = 0; i < 2; i++) {
        /**
         * @brief generate AES key, iv
         * @note write_key = salt(traffic_secret), expand_label("key", "", key_length)
         * @note write_iv = salt(traffic_secret), expand_label("iv", "", iv_length);
        */
        hkdf_.salt(&secret[i][0], secret[i].size());
        auto key = hkdf_.expand_label("key", "", 16);
        auto iv = hkdf_.expand_label("iv", "", 12);
        this->aes_[i].key(&key[0], key.size());//set AES key
        this->aes_[i].iv(&iv[i], iv.size());//set AES iv

        /**
         * @brief generate finished_key
         * @note finished_key = salt(traffic_secret), expand_label("finished", "", key_size)
        */
        finished_key[i] = hkdf_.expand_label("finished", "", HASH::SHA2::output_size);
    }
    return finished_key;
}

template<bool SV>
void TLS13::TLS13<SV>::protect_data() {//server finished 직후에 호출
    set_aes(this->master_secret_, "c ap traffic", "s ap traffic");
}