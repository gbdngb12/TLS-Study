#include<algorithm>
#include <catch2/catch_all.hpp>
#include "hash.h"
#include "util.h"
using namespace std;
using namespace UTIL;
TEST_CASE("HKDF") {
	HASH::HKDF<HASH::SHA2> hkdf;
	mpz_class IKM{"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"},//22
			  SALT{"0x000102030405060708090a0b0c"},//13
			  INFO{"0xf0f1f2f3f4f5f6f7f8f9"},//10
			  PRK{"0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"},//32
			  OKM{"0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"};//42
	unsigned char ikm[22], salt[13], info[10], prk[32], okm[42];
	mpz_to_bnd(IKM, ikm, ikm + 22);
	mpz_to_bnd(SALT, salt, salt + 13);
	mpz_to_bnd(INFO, info, info + 10);
	mpz_to_bnd(PRK, prk, prk + 32);
	mpz_to_bnd(OKM, okm, okm + 42);
	hkdf.salt(salt, 13);
	auto a = hkdf.extract(ikm, 22);
	REQUIRE(equal(a.begin(), a.end(), prk));
	hkdf.salt(&a[0], a.size());
	auto b = hkdf.expand(string{info, info + 10}, 42);
	REQUIRE(equal(b.begin(), b.end(), okm));
}