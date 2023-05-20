#pragma once
#include <gmpxx.h>

#include "key_exchange.h"
/**
 * @brief y^2 = x^3 + ax + b (mod) mod
 *
 */
class EllipticCurveField {
   public:
    EllipticCurveField(mpz_class a, mpz_class b, mpz_class mod);
    /**
     * @brief r의 모듈러 역원을 구함
     *
     * @param r 구하고자 하는 값
     * @return mpz_class r의 모듈러 역원
     */
    mpz_class mod_inv(const mpz_class& r) const;

    EllipticCurveField(const EllipticCurveField&&) noexcept = default;
    EllipticCurveField& operator=(const EllipticCurveField&&) noexcept = default;

   private:
    mpz_class a,
        b, mod;
};
namespace tls::key_exchange {

/**
 * @brief 타원 곡선 클래스
 *
 * @tparam private_key_type 개인키
 * @tparam public_key_type 공개키
 * @tparam shared_key_type 공유 세션키
 */
template <typename private_key_type, typename public_key_type, typename shared_key_type>
class EllipticCurve : public KeyExchange<private_key_type, public_key_type, shared_key_type> {
   public:
    EllipticCurve(private_key_type private_key, public_key_type public_key);
    /**
     * @brief 상대방의 공개키를 설정한다.
     *
     * @param peer_public_key 상대방의 공개키
     * @return public_key_type 설정한 상대방의 공개키
     */
    virtual public_key_type set_peer_pubkey(public_key_type peer_public_key) noexcept override;
    /**
     * @brief 공유 세션키를 생성한다.
     *
     */
    virtual void set_shared_key() noexcept override;

   private:
};
};  // namespace tls::key_exchange
