#include <catch2/catch_all.hpp>

#include <iostream>
#include <algorithm>
using namespace std;

TEST_CASE("test name") {
    vector<int> a, b;
    int c, d;

    a.push_back(4);
    a.push_back(5);

    b.push_back(5);
    b.push_back(4);

    c = 3;
    d = 3;
    REQUIRE(equal(a.begin(), a.end(), b.begin()));
}