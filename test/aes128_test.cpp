#include <nettle/gcm.h>
#include <openssl/evp.h>

#include <catch2/catch_all.hpp>
#include <iostream>

#include "util.h"
#define private public
#define protected public
#include "aes128.h"
#undef private
#undef protected

/*TEST_CASE("CBC") {
    AES128::CBC<AES128::AES> cbc;
    std::cout << "CBC PAdding Test" << std::endl;
    unsigned char key[16] = {
        14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14};
    unsigned char iv[16] = {
        1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    cbc.key(key);
    cbc.iv(iv);
    // 32 - 19 + 1
    std::string msg = "Hello this is test";  // 18byte -> need to 14byte padding 13 13 13 13 ... 13
    for (int i = 0; i < 14; i++) {
        msg += 13;
    }
    cbc.encrypt((unsigned char *)msg.data(), 32);
    cbc.decrypt((unsigned char *)msg.data(), 32);
    for (int i = msg.back(); i >= 0; i--) {
        msg.pop_back();  // remove padiing
    }
    REQUIRE(msg == "Hello this is test");
}

TEST_CASE("shift_row & mix column") {
        std::cout << "shift_row & mix column Test" << std::endl;
    AES128::AES aes;
        unsigned char data[16], oneto16[16];
        for(int i=0; i<16; i++) data[i] = oneto16[i] = i+1;
        unsigned char shift_row_result[16]
                = { 1, 6, 0x0b, 0x10, 5, 0xa, 0xf, 4, 9, 0xe, 3, 8, 0xd, 2, 7, 0xc };
        unsigned char mix_comlumn_result[16]
                = {3, 4, 9, 0xa, 0xf, 8, 0x15, 0x1e, 0xb, 0xc, 1, 2, 0x17, 0x10, 0x2d, 0x36};

        aes.shift_row(data);
        REQUIRE(std::equal(data, data + 16, shift_row_result));
        aes.inv_shift_row(data);
        REQUIRE(std::equal(data, data + 16, oneto16));

        aes.mix_column(data);
        REQUIRE(std::equal(data, data + 16, mix_comlumn_result));
    aes.inv_mix_column(data);
        REQUIRE(std::equal(data, data + 16, oneto16));
}

unsigned char schedule[11 * 16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
        0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75,
        0xE2, 0x32, 0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88,
        0xB1, 0x59, 0xE4, 0xE6, 0xD6, 0x79, 0xA2, 0x93,
        0x56, 0x08, 0x20, 0x07, 0xC7, 0x1A, 0xB1, 0x8F,
        0x76, 0x43, 0x55, 0x69, 0xA0, 0x3A, 0xF7, 0xFA,
        0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A, 0xBC, 0x68,
        0x63, 0x39, 0xE9, 0x01, 0xC3, 0x03, 0x1E, 0xFB,
        0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1,
        0xD7, 0x51, 0x57, 0xA0, 0x14, 0x52, 0x49, 0x5B,
        0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92,
        0xD2, 0x10, 0xD2, 0x32, 0xC6, 0x42, 0x9B, 0x69,
        0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15,
        0x6A, 0x6C, 0x95, 0x27, 0xAC, 0x2E, 0x0E, 0x4E,
        0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03,
        0x1E, 0x86, 0x3F, 0x24, 0xB2, 0xA8, 0x31, 0x6A,
        0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22,
        0xE4, 0x3D, 0x7A, 0x06, 0x56, 0x95, 0x4B, 0x6C,
        0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2,
        0xA1, 0x64, 0x80, 0xB4, 0xF7, 0xF1, 0xCB, 0xD8,
        0x28, 0xFD, 0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A,
        0xCC, 0xC0, 0xA4, 0xFE, 0x3B, 0x31, 0x6F, 0x26
};

TEST_CASE("key scheduling") {
    AES128::AES aes;
        std::cout << "Key Scheduling Test" << std::endl;
    aes.key(schedule);//첫 16바이트만 키값으로 주어진다.
    REQUIRE(std::equal(schedule, schedule + 11 * 16, aes.schedule_[0]));
}*/
// 20230210 해야할 일 :
// openssl을 이용한 gcm_aes128 암호화, 복호화 태그 테스트 함수 구현
// 내가 만든 gcm 복호화 태그와 값 비교

bool openssl_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                     unsigned char *iv, unsigned char *aad, int aad_len,
                     unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12 /*12bytes*/, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* set aad */
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Provide the message to be encrypted, and obtain the ciphertext */
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    /* Finalise the encryption */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool openssl_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                     unsigned char *iv, unsigned char *aad, int aad_len,
                     unsigned char *plaintext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12 /*12 byte*/, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Provide the message to be decrypted, and obtain the plaintext */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }


    /* Provide the message to be decrypted, and obtain the plaintext */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

TEST_CASE("GCM") {
    unsigned char key[16], auth_data[28], IV[12], plain_text1[48], plain_text2[48], plain_text3[48], aad1[16], aad2[16],  cipher_text1[48], cipher_text2[48], cipher_text3[48];
    UTIL::mpz_to_bnd(UTIL::random_prime(16), key, key + 16);                  // key
    UTIL::mpz_to_bnd(UTIL::random_prime(70), auth_data, auth_data + 28);      // Auth Data
    UTIL::mpz_to_bnd(UTIL::random_prime(12), IV, IV + 12);                    // iv
    UTIL::mpz_to_bnd(UTIL::random_prime(48), plain_text1, plain_text1 + 48);  // plain text
    memcpy(plain_text2, plain_text1, 48);
    memcpy(plain_text3, plain_text1, 48);

    SECTION("nettle , openssl, my class COMPARE") {
        // nettle 라이브러리로 암호화
        gcm_aes128_ctx ctx;
        gcm_aes128_set_key(&ctx, key);
        gcm_aes128_set_iv(&ctx, 12, IV);
        gcm_aes128_update(&ctx, 28, auth_data);                   // Auth Data
        gcm_aes128_encrypt(&ctx, 48, cipher_text1, plain_text1);  // Cipher text
        gcm_aes128_digest(&ctx, 16, aad1);                        // aad1 : Auth Tag


        memset(&ctx,0, sizeof(ctx));
        memset(plain_text1, 0, 48);

        unsigned char de_aad1[16];

        gcm_aes128_set_key(&ctx, key);
        gcm_aes128_set_iv(&ctx, 12, IV);
        gcm_aes128_update(&ctx, 28, auth_data);//set auth_data
        gcm_aes128_decrypt(&ctx, 48, plain_text1, cipher_text1);
        gcm_aes128_digest(&ctx,16, de_aad1);

        ////////////////////////////////////////////////

        //openssl
        if(!openssl_encrypt(plain_text2, 48, key, IV, auth_data, 28, cipher_text2, aad2)) {
            std::cout<< "error" << std::endl;
            exit(1);
        }
        memset(plain_text2, 0, 48);

        if(!openssl_decrypt(cipher_text2, 48, key, IV, auth_data, 28, plain_text2, aad2)) {
            std::cout<< "error" << std::endl;
            exit(1);
        }



        AES128::GCM<AES128::AES> gcm;
        gcm.iv(IV);
        gcm.key(key);
        gcm.aad(auth_data, 28);
        auto aad3 = gcm.encrypt(plain_text3, 48);
        memcpy(cipher_text3, plain_text3, 48);

        AES128::GCM<AES128::AES> gcm2;
        gcm2.iv(IV);
        gcm2.key(key);
        gcm2.aad(auth_data, 28);
        auto de_aad3 = gcm2.decrypt(plain_text3, 48);


        //Compare Cipher Text
        REQUIRE(std::equal(cipher_text1, cipher_text1 + 48, cipher_text2));//nettle, openssl
        REQUIRE(std::equal(cipher_text1, cipher_text1 + 48, cipher_text3));//nettle, my class
        REQUIRE(std::equal(cipher_text2, cipher_text2 + 48, cipher_text3));//openssl, my class

        //Compare Decrypt Text
        REQUIRE(std::equal(plain_text1, plain_text1 + 48, plain_text2));//nettle, openssl
        REQUIRE(std::equal(plain_text1, plain_text1 + 48, plain_text3));//nettle, my class
        REQUIRE(std::equal(plain_text2, plain_text2 + 48, plain_text3));//openssl, my class

        //생성된 Auth Tag Compare
        REQUIRE(std::equal(aad1, aad1 + 16, aad2));//nettle, openssl
        REQUIRE(std::equal(aad1, aad1 + 16, aad3.begin()));//nettle, my class
        REQUIRE(std::equal(aad2, aad2 + 16, aad3.begin()));//openssl, my class
        
        //복호화후 Auth Tag 비교(openssl은 tag값이 정확하지 않으면 오류 발생 하므로 비교할 필요가 없다.)
        REQUIRE(std::equal(de_aad1, de_aad1 + 16, de_aad3.begin()));//nettle, my class
    }
}