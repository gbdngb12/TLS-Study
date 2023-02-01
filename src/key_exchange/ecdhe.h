#pragma once
#include <gmpxx.h>
#include "util.h"
#include <iostream>

namespace EllipticCurveDHE {

class EC_Field {  // y^2 = x^3 + ax + b ( mod mod )
   public:
    EC_Field(mpz_class a, mpz_class b, mpz_class mod);

   protected:
    mpz_class a, b, mod;
    mpz_class mod_inv(const mpz_class &r) const;//나머지 역원을 구하는 함수
};

class EC_Point : EC_Field { // EC_Field 상의 한 좌표
public:
    EC_Point(mpz_class x, mpz_class y, const EC_Field &f);
    mpz_class x, y;// x, y
    EC_Point operator+(const EC_Point &r) const; //두 좌표의 합
    EC_Point operator*(const mpz_class &r) const;// P * k
    bool operator==(const EC_Point &r) const;
};
};

std::ostream& operator<<(std::ostream &is, const EllipticCurveDHE::EC_Point &r);//타원곡선 점 출력 함수
EllipticCurveDHE::EC_Point operator*(const mpz_class &l, const EllipticCurveDHE::EC_Point &r);// k * P