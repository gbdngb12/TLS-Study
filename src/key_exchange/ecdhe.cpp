#include "ecdhe.h"

EllipticCurveDHE::EC_Field::EC_Field(mpz_class a, mpz_class b, mpz_class mod) {  // y^2 = x^3 + ax + b ( mod mod )
    this->a = a;
    this->b = b;
    this->mod = mod;
}

mpz_class EllipticCurveDHE::EC_Field::mod_inv(const mpz_class &z) const {  // 나머지 역원을 구하는 함수
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
    return r;
}

EllipticCurveDHE::EC_Point::EC_Point(mpz_class x, mpz_class y, const EC_Field &f) : EC_Field{f} {
    //std::cout << "Check" << "(" << x << ", " << y << ")" << std::endl;
    if (y != mod) assert((y * y - (x * x * x + a * x + b)) % mod == 0);  // 좌표가 유한체의 원소인지 확인한다.
    this->x = x;
    this->y = y;
}

bool EllipticCurveDHE::EC_Point::operator==(const EC_Point &r) const {
    assert(a == r.a && b == r.b && mod == r.mod);  // 같은 타원곡선 방정식
    return x == r.x && y == r.y;                   // 좌표가 같은지 확인한다.
}

EllipticCurveDHE::EC_Point EllipticCurveDHE::EC_Point::operator+(const EC_Point &r) const {  // 두 좌표의 합
    // y값이 mod와 같은 것을 O(항등원, 무한)
    if (r.y == mod) return *this;                            // P + O = P
    if (y == mod) return r;                                  // O + P = P
    mpz_class s;                                             // slope
    if (r == *this) {                                        // P == Q인 경우
        if (y == 0) return {x, mod, *this};                  // 항등원 리턴
        s = ((3 * x * x + a) * mod_inv(2 * this->y)) % mod;  //(3*x^2 + a) * mod_inv(2*y)
    } else {                                                 // P != Q인 경우
        if (x == r.x) return {x, mod, *this};                // 항등원 리턴
        s = ((r.y - y) * mod_inv(r.x - x)) % mod;
    }
    mpz_class x3 = (s * s - x - r.x) % mod;//s^2 - x_p - x_q  % mod
    mpz_class y3 = (s * (x - x3) - y) % mod;//(s(x_p - x_r) - y_p ) % mod
    return {x3 < 0 ? x3 + mod : x3/*mod값이 음수라면 +mod해서 리턴*/, y3 < 0 ? y3 + mod : y3, *this}; //fucking 오타났었음 x3값을 확인해야 하는데 x값을 확인함
}

EllipticCurveDHE::EC_Point EllipticCurveDHE::EC_Point::operator*(mpz_class r) const { //P * k
    std::vector<bool> bits; //r을 bit 단위로 저장
    for(; r > 0; r /= 2) {
        bits.push_back(r % 2 == 1);
    }
    EC_Point X = *this, R{0, mod, *this}/*항등원*/;
    for(auto a : bits) {
        if(a) {//비트가 1이면 그대로 더함
            R = R + X;
        }
        X = X + X;//X, 2X, 4X, 8X, ...., 
    }
    return R;
}

EllipticCurveDHE::EC_Point operator*(const mpz_class &l, const EllipticCurveDHE::EC_Point &r) { //k * P
    return r * l;
}

std::ostream& operator<<(std::ostream &is, const EllipticCurveDHE::EC_Point &r) {
    is << "( "<< r.x << ", " << r.y << " )";
    return is;
}