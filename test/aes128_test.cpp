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