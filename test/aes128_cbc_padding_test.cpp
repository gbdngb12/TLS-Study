#include <catch2/catch_all.hpp>
#include <iostream>
#define private public
#define protected public
#include "aes128.h"
#undef private
#undef protected

/*TEST_CASE("mixcolunm") {
    unsigned char inv[16] = {
        14,9,13,11,11,14,9,13,13,11,14,9,9,13,11,14
    };
    AES128::AES aes;
    unsigned char o[16] = { 1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1};
    aes.mix_column(inv);
    REQUIRE(std::equal(inv, inv + 16, o)); 
}*/
/*TEST_CASE("CBC") {
    AES128::CBC<AES128::AES> cbc;
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
}*/

TEST_CASE("shift_row & mix column") {
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
