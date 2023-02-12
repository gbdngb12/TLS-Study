#include "hash.h"

#include <catch2/catch_all.hpp>
#include <string>
#include <iostream>
#include "util.h"

TEST_CASE("sha1") {
    const std::string s[] = {"abc",
                             "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                             "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
    const char *result[] = {"0xa9993e364706816aba3e25717850c26c9cd0d89d",
                            "0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                            "0xa49b2446a02c645bf419f995b67091253a04a259"};
    unsigned char nresult[20];
	std::cout << "sha1 test case" << std::endl;
    HASH::SHA1 sha;
    for (int i = 0; i < 3; i++) {
        UTIL::mpz_to_bnd(mpz_class{result[i]}, nresult, nresult + 20);
        auto a = sha.hash(s[i].begin(), s[i].end());
        REQUIRE(std::equal(a.begin(), a.end(), nresult));
    }
}

TEST_CASE("hmac") {
	const std::string data[] = {
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen",
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen, with truncated tag"
	};
	const char *key[] = {
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
		"0x000102030405060708090A0B0C0D0E0F10111213",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424\
			34445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F30"
	};
	const char *result[] = {"0x5FD596EE78D5553C8FF4E72D266DFD192366DA29",
							"0x4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
							"0x2D51B2F7750E410584662E38F133435F4C4FD42A",
							"0xFE3529565CD8E28C5FA79EAC9D8023B53B289D96"};

	int data_len[] = {34, 34, 34, 54};
	int key_len[] = {64, 20, 100, 49};
	unsigned char nkey[100], nresult[32];

	HASH::HMAC<HASH::SHA1> hmac;
	for(int i=0; i<4; i++) {
		UTIL::mpz_to_bnd(mpz_class{key[i]}, nkey, nkey + key_len[i]);
		UTIL::mpz_to_bnd(mpz_class{result[i]}, nresult, nresult + 20);
		hmac.key(nkey, nkey + key_len[i]);
		auto a = hmac.hash(data[i].begin(), data[i].end());
		REQUIRE(std::equal(a.begin(), a.end(), nresult));
	}
}