#pragma once
// Code that requires the feature
#include <arpa/inet.h>
#include <nettle/sha2.h>
#include <string>
#include <array>
#include <cstdint>
#include <cstring>
#include <valarray>
#include <vector>

namespace HASH {
class SHA1 {
   public:
    static const int block_size = 64;   // byte
    static const int output_size = 20;  // byte
    SHA1();
    template <class It>
    std::array<unsigned char, output_size> hash(const It begin, const It end) {
        for (int i = 0; i < 5; i++) {
            h[i] = h_stored_value[i];
        }
        std::vector<unsigned char> msg(begin, end);
        preprocess(msg);
        for (int i = 0; i < msg.size(); i += 64) {  // 메시지 블록에 대해서 연속적으로 해쉬 수행
            process_chunk(&msg[i]);
        }
        if (!big_endian_) {  // little endian이면 big endian 형식으로 저장
            for (int i = 0; i < 5; i++) {
                h[i] = htonl(h[i]);
            }
        }
        std::array<unsigned char, output_size> digest;
        unsigned char *p = (unsigned char *)h;  // 최종 h를 연결하여 digest 완성
        for (int i = 0; i < output_size; i++) {
            digest[i] = *p++;
        }
        return digest;
    }
    static uint32_t left_rotate(uint32_t a, int bits);

   protected:
    bool big_endian_ = false;
    uint32_t h[5] /*결과 해쉬 계산 값*/, w[80] /*64byte배열 -> 4byte배열로 변환*/;
    static constexpr uint32_t h_stored_value[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};  // h초기값
   private:
    static void preprocess(std::vector<unsigned char> &v);
    void process_chunk(unsigned char *p);  // 64바이트 블록 hash수행
};

class SHA2 {
   public:
    static const int block_size = 64;   // byte
    static const int output_size = 32;  // byte
    SHA2();
    template <typename It>
    std::array<unsigned char, output_size>
    hash(const It begin, const It end) {
        std::array<unsigned char, output_size> r;
        sha256_update(&sha_, end - begin, (const unsigned char *)&*begin);
        sha256_digest(&sha_, output_size, &r[0]);
        return r;
    }

   protected:
    sha256_ctx sha_;
};

template <class H>
class HMAC {
   public:
    HMAC() : o_key_pad_(H::block_size), i_key_pad_(H::block_size) {}
    template <typename It>
    void key(const It begin, const It end) {
        int length = end - begin;
        // key, o_key_pad, i_key_pad 연산을 위한 상수 및 저장공간
        std::valarray<unsigned char> key((int)0x00, H::block_size), out_xor(0x5c, H::block_size), in_xor(0x36, H::block_size);

        // block_size보다 크면 해쉬, 작으면 0패딩
        if (length > H::block_size) {
            auto h = sha_.hash(begin, end);
            for (int i = 0; i < H::output_size; i++) {
                key[i] = h[i];
            }
        } else if (int i = 0; length <= H::block_size) {  // c++17 initializer
            // 0 padiing
            for (auto it = begin; it != end; it++) {
                key[i++] = *it;
            }
        }
        // o_key_pad 연산, i_key_pad 연산
        o_key_pad_ = key ^ out_xor;
        i_key_pad_ = key ^ in_xor;
    }

    template <typename It>
    auto hash(const It begin, const It end) {
        std::vector<unsigned char> v;
        // hash(i_key_pad | message)
        v.insert(v.begin(), std::begin(i_key_pad_), std::end(i_key_pad_));
        v.insert(v.end(), begin, end);
        auto h = sha_.hash(v.begin(), v.end());

        // hash(o_key_pad | hash(i_key_pad | message))
        v.clear();
        v.insert(v.begin(), std::begin(o_key_pad_), std::end(o_key_pad_));
        v.insert(v.end(), h.begin(), h.end());
        return sha_.hash(v.begin(), v.end());
    }

   protected:
    H sha_;  // SHA Hash Family
    std::valarray<unsigned char> o_key_pad_, i_key_pad_;
};

template <class H>
class PRF {  // H is Hash Function
   public:
    /*!
    @brief 확장하고자 하는 secret값을 설정한다
    @param begin secret Iterator 시작
    @param end secret Iterator 끝
    */
    template <class It>
    void secret(const It begin, const It end) {
        hmac_.key(begin, end);
    }

    /*!
    @brief PRF label값을 설정한다.
    @param p const char *label
    */
    void label(const char *p) {
        label_.clear();
        while (*p) label_.push_back(*p++);
    }

    /*!
    @brief PRF seed값을 설정한다.
    @param begin seed Iterator 시작
    @param end seed Iterator 끝
    */
    template <class It>
    void seed(const It begin, const It end) {
        seed_.clear();
        for (It it = begin; it != end; it++) {
            seed_.push_back(*it);
        }
    }

    /*!
    @brief 랜덤 n바이트로 확장한다.
    @param n 확장할 바이트 수
    @return 확장한 n바이트 vector
    */
    std::vector<unsigned char> expand_n_byte(int n) {
        // seed = label + seed_
        auto seed = label_;
        seed.insert(seed.end(), seed_.begin(), seed_.end());  // A(0) = seed

        std::vector<unsigned char> r, v;

        for (auto A = hmac_.hash(seed.begin(), seed.end());    // A(1) = HMAC(secret, seed)
             r.size() < n;                                     // n바이트 보다 작게
             A = hmac_.hash(A.begin(), A.end()), v.clear()) {  // A(i) = HMAC(secret, A(i - 1))
            v.insert(v.end(), A.begin(), A.end());             // A(1)
            v.insert(v.end(), seed.begin(), seed.end());       // v = A(1) + seed
            auto h = hmac_.hash(v.begin(), v.end());
            r.insert(r.end(), h.begin(), h.end());  // r = h(secret, A(1) + seed) + h(secret, A(2) + seed) + ... +
        }
        // 크기가 작다면 0 padding
        // 크기가 크다면 자름
        r.resize(n);  // 리턴할 벡터 크기 n바이트로 조절
        return r;
    }

   protected:
    HMAC<H> hmac_;
    std::vector<unsigned char> label_, seed_;
};

template <class H>
class HKDF : public HMAC<H> {
   public:
    /**
     * @brief salt값을 해쉬 함수의 output 길이만큼 0으로 채운다.
     */
    void zero_salt() {
        uint8_t zeros[H::output_size] = {0};
        HMAC<H>::key(zeros, zeros + H::output_size);
    }
    /**
     * @brief salt값을 설정한다.
     * @param p 설정할 salt값
     * @param sz 설정할 salt 크기
     */
    void salt(uint8_t *p, int sz) {
        this->key(p, p + sz);
    }
    /**
     * @brief p값을 salt를 key로 해쉬한다.
     * @param p 해쉬할 input값
     * @param sz 해쉬하는 input의 크기
     * @return p를 해쉬한값
     */
    std::vector<uint8_t> extract(uint8_t *p, int sz) {
        auto a = this->hash(p, p + sz);
        return std::vector<uint8_t>{a.begin(), a.end()};
    }
    /**
     * @brief salt를 key로 하여 info를 label로하여 L길이로 해쉬 확장한다.
     * @param info label
     * @param L 확장하고자하는 길이
     * @return L만큼 확장된 값
     */
    std::vector<uint8_t> expand(std::string info, int L) {
        std::vector<uint8_t> r;
        int k = H::output_size + info.size() + 1 /*counter의 크기*/;  // hash할 구조체의 크기
        uint8_t t[k];                                                 // 해쉬할 구조체
        memcpy(t + H::output_size, info.data(), info.size());         // T(0) + info
        t[k - 1] = 1;                                                 // T(0) + info + 1
        auto a = HMAC<H>::hash(t + H::output_size, t + k);//T(1) = HMAC(info + 1)
        r.insert(r.end(), a.begin(), a.end());//T(1)
        while(r.size() < L) {
            memcpy(t, &a[0], a.size());//T(1) + info + 1
            t[k - 1]++;//T(1) + info + 2
            a = HMAC<H>::hash(t, t + k);//T(2) = HMAC(T(1) + info + 2)
            r.insert(r.end(), a.begin(), a.end());
        }
        r.resize(L);
        return r;
    }
    /**
     * @brief expand_label함수를 호출한다
     * @param label label
     * @param msg context
     * @return 해쉬의 길이만큼 확장된 값
     */
    std::vector<uint8_t> derive_secret(std::string label, std::string msg) {
        auto a = this->sha_.hash(msg.begin(), msg.end());
        return expand_label(label, std::string{a.begin(), a.end()}, H::output_size);
    }

   private:
    /**
     * @brief label과 context를 이용하여 새로운 label을 만들고 L길이만큼 확장한다.
     * @param label label
     * @param context context
     * @param L 확장하고자 하는 길이
     * @return L만큼 확장된 값
     */
    std::vector<uint8_t> expand_label(std::string label, std::string context, int L) {
        std::string hkdf_label = "xxxtls13 " + label + 'x' + context;
        hkdf_label[0] = L / 0x100;
        hkdf_label[1] = L % 0x100;
        hkdf_label[label.size() + 9]/*context Length 자리*/ = context.size();
        return expand(hkdf_label, L);
    }
};

}  // namespace HASH
