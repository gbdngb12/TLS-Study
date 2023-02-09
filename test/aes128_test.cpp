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
//20230210 해야할 일 :
//openssl을 이용한 gcm_aes128 암호화, 복호화 태그 테스트 함수 구현
//내가 만든 gcm 복호화 태그와 값 비교
TEST_CASE("GCM") {
    int plaintext_len = 48;
    int len;
    int ciphertext_len;
    unsigned char K[16], A[70], IV[12], P[48], Z[16], Z2[16] ={ 0 }, C[48], C2[48] = {0}, B[16], Z3[16] ={ 0 };
    UTIL::mpz_to_bnd(UTIL::random_prime(16), K, K + 16);    // key
    UTIL::mpz_to_bnd(UTIL::random_prime(70), A, A + 70);    // Auth Data
    UTIL::mpz_to_bnd(UTIL::random_prime(12), IV, IV + 12);  // iv
    UTIL::mpz_to_bnd(UTIL::random_prime(48), P, P + 48);    // plain text

	int enc = 1;
	int dec = 0;
    SECTION("GCM compare with nettle") {
        // openssl
        EVP_CIPHER_CTX *openssl_ctx;
        openssl_ctx = EVP_CIPHER_CTX_new();
        /* Don't set key or IV right away; we want to check lengths */
        if (!EVP_CipherInit_ex2(openssl_ctx, EVP_aes_128_gcm(), NULL, NULL,
                                enc, NULL)) {
            /* Error */
            EVP_CIPHER_CTX_free(openssl_ctx);
            exit(1);
        }
        OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(openssl_ctx) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(openssl_ctx) == 12);

    	/* Now we can set key and IV */
    	if (!EVP_EncryptInit_ex(openssl_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
    	    /* Error */
    	    EVP_CIPHER_CTX_free(openssl_ctx);
    	    exit(1);
    	}

        if(!EVP_CIPHER_CTX_ctrl(openssl_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(openssl_ctx);
    	    exit(1);
        }

         /* Initialise key and IV */
        if(!EVP_EncryptInit_ex(openssl_ctx, NULL, NULL, K, IV)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(openssl_ctx);
    	    exit(1);
        }

        //set aad
        if(!EVP_EncryptUpdate(openssl_ctx, NULL, &len, A, 28)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(openssl_ctx);
    	    exit(1);
        }

		if (!EVP_CipherUpdate(openssl_ctx, C, &len, P, plaintext_len)) {
            /* Error */
            EVP_CIPHER_CTX_free(openssl_ctx);
            exit(1);
        }
        ciphertext_len = len;

		if (!EVP_CipherFinal_ex(openssl_ctx, C + len, &len)) {
        	/* Error */
        	EVP_CIPHER_CTX_free(openssl_ctx);
        	exit(1);
    	}
        ciphertext_len += len;
        /* Get the tag */
        if(!EVP_CIPHER_CTX_ctrl(openssl_ctx, EVP_CTRL_GCM_GET_TAG, 16, Z)) {
            /* Error */
        	EVP_CIPHER_CTX_free(openssl_ctx);
        	exit(1);
        }
        ciphertext_len += 16;
		
		EVP_CIPHER_CTX_free(openssl_ctx);


        gcm_aes128_ctx ctx;  // nettle 라이브러리로 암호화
        gcm_aes128_set_key(&ctx, K);
        gcm_aes128_set_iv(&ctx, 12, IV);
        gcm_aes128_update(&ctx, 28, A);      // A : Auth Data
        gcm_aes128_encrypt(&ctx, 48, C2, P);  // C: Cipher text
        gcm_aes128_digest(&ctx, 16, Z2);      // Z : Auth Tag


        int plaintext_len2 = 48;
        int len2;
        int ciphertext_len2;

        EVP_CIPHER_CTX *decrypt_ctx;
        if(decrypt_ctx = EVP_CIPHER_CTX_new()) {
            /* Error */
        	EVP_CIPHER_CTX_free(decrypt_ctx);
        	exit(1);
        }

        if(!EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
            /* Error */
        	EVP_CIPHER_CTX_free(decrypt_ctx);
        	exit(1);
        }
        if(!EVP_CIPHER_CTX_ctrl(decrypt_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)){
            /* Error */
        	EVP_CIPHER_CTX_free(decrypt_ctx);
        	exit(1);
        }

        /* Initialise key and IV */
        if (!EVP_DecryptInit_ex(decrypt_ctx, NULL, NULL, K, IV)) {
                /* Error */
                EVP_CIPHER_CTX_free(decrypt_ctx);
                exit(1);
        }

        if(!EVP_EncryptUpdate(decrypt_ctx, NULL, &len, A, 28)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(decrypt_ctx);
    	    exit(1);
        }

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(decrypt_ctx, EVP_CTRL_GCM_SET_TAG, 16, Z/*tag*/)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(decrypt_ctx);
    	    exit(1);
        }

        if(!EVP_DecryptUpdate(decrypt_ctx, NULL, &len, B/*aad*/, 16/*aad_len*/)) {
            /* Error */
    	    EVP_CIPHER_CTX_free(decrypt_ctx);
    	    exit(1);
        }






        AES128::GCM<AES128::AES> gcm;  // 직접 만든 클래스로 암호화
        gcm.iv(IV);
        gcm.key(K);
        gcm.aad(A, 28);
        auto a = gcm.encrypt(P, 48);  // P의 위치에 암호문을 덮어쓴다.

        REQUIRE(std::equal(P, P + 48, C));           // nettle암호문과 비고
        REQUIRE(std::equal(a.begin(), a.end(), Z));  // nettle과 인증 태그 비교

        auto b = gcm.decrypt(P, 48);  // P의 위치에 원문 복호화, b는 복호화 하면서 생긴 인증 태그값

        //gcm_aes128_set_key(&ctx, K);
        //gcm_aes128_set_iv(&ctx, 12, IV);
        //gcm_aes128_update(&ctx, 28, A);      // A : Auth Data
        //gcm_aes128_decrypt(&ctx, 48, D, C);  // D : Decrypt Text
        //gcm_aes128_digest(&ctx, 16, B);

        //REQUIRE(std::equal(P, P + 48, D));
        //REQUIRE(std::equal(b.begin(), b.end(), a.begin()));*/
    }
}

/*TEST_CASE("GCM") {
        unsigned char K[16], A[70], IV[12], P[48], Z[16], C[48];
        UTIL::mpz_to_bnd(UTIL::random_prime(16), K, K + 16);
        UTIL::mpz_to_bnd(UTIL::random_prime(70), A, A + 70);
        UTIL::mpz_to_bnd(UTIL::random_prime(12), IV, IV + 12);
        UTIL::mpz_to_bnd(UTIL::random_prime(48), P, P + 48);
        SECTION("GCM compare with nettle") {
                gcm_aes128_ctx ctx;
                gcm_aes128_set_key(&ctx, K);
                gcm_aes128_set_iv(&ctx, 12, IV);
                gcm_aes128_update(&ctx, 28, A);
                gcm_aes128_encrypt(&ctx, 48, C, P);
                gcm_aes128_digest(&ctx, 16, Z);

                AES128::GCM<AES128::AES> gcm;
                gcm.iv(IV);
                gcm.key(K);
                gcm.aad(A, 28);
                auto a = gcm.encrypt(P, 48);
                REQUIRE(std::equal(P, P+48, C));
                REQUIRE(std::equal(a.begin(), a.end(), Z));

                UTIL::mpz_to_bnd(UTIL::random_prime(12), IV, IV+12);
                UTIL::mpz_to_bnd(UTIL::random_prime(70), A, A + 70);
                gcm_aes128_set_iv(&ctx, 12, IV);
                gcm_aes128_update(&ctx, 28, A);
                gcm_aes128_encrypt(&ctx, 48, C, P);
                gcm_aes128_digest(&ctx, 16, Z);

                gcm.iv(IV);
                gcm.aad(A, 28);
                a = gcm.encrypt(P, 48);
                REQUIRE(std::equal(P, P+48, C));
                REQUIRE(std::equal(a.begin(), a.end(), Z));
        }
}*/