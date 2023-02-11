#include <catch2/catch_all.hpp>
#include "util.h"
#include "hash.h"
#include <string>

TEST_CASE("sha1") {
	const std::string s[] = {"abc", 
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
	const char *result[] = {"0xa9993e364706816aba3e25717850c26c9cd0d89d",
							"0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
							"0xa49b2446a02c645bf419f995b67091253a04a259"};
	unsigned char nresult[20];
	HASH::SHA1 sha;
	for(int i=0; i<3; i++) {
		UTIL::mpz_to_bnd(mpz_class{result[i]}, nresult, nresult + 20);
		auto a = sha.hash(s[i].begin(), s[i].end());
		REQUIRE(std::equal(a.begin(), a.end(), nresult));
	}
}