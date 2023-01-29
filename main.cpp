#include <catch2/catch_all.hpp>

#include "util.h"

TEST_CASE("test name") {
    uint8_t arr[8];
    mpz_class a{"0x1234567890abcdef"};
    Util::mpz_to_bnd(a, arr, arr + 8);
    mpz_class b = Util::bnd_to_mpz(arr, arr + 8);
    REQUIRE(a == b);
}