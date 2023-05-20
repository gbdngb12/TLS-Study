#include "elliptic_curve.h"

#include <utility>
namespace tls::key_exchange {

template <typename private_key_type, typename public_key_type, typename shared_key_type>
EllipticCurve<private_key_type, public_key_type, shared_key_type>::
    EllipticCurve(private_key_type private_key, public_key_type public_key)
    : m_private_key{std::move(private_key)}, m_public_key{std::move(public_key)} {}

template <typename private_key_type, typename public_key_type, typename shared_key_type>
public_key_type EllipticCurve<private_key_type, public_key_type, shared_key_type>::
    set_peer_pubkey(public_key_type peer_public_key) noexcept {
    m_peer_public_key{std::move(peer_public_key)};
    set_shared_key();
}

template <typename private_key_type, typename public_key_type, typename shared_key_type>
void EllipticCurve<private_key_type, public_key_type, shared_key_type>::set_shared_key() noexcept {
    m_shared_key{std::move(m_private_key * m_peer_public_key)};
}

// 인스턴스화
template class EllipticCurve<mpz_class, EllipticCurveField, EllipticCurveField>;
};  // namespace tls::key_exchange

EllipticCurveField::
    EllipticCurveField(mpz_class p_a, mpz_class p_b, mpz_class p_mod)
    : a{p_a}, b{p_b}, mod{p_mod} {}

mpz_class EllipticCurveField::mod_inv(const mpz_class& z) const {
    mpz_class r;
    /**
     * @brief r에 z의 mod 역원을 저장함
     *
     */
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
    return r;
}