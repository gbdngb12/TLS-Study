#pragma once
#include <arpa/inet.h>
#include <nettle/sha2.h>

#include <cstring>
#include <array>
#include <cstdint>
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
}  // namespace HASH
