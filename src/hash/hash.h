#pragma once
#include <arpa/inet.h>

#include <array>
#include <cstdint>
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
}  // namespace HASH