#include "dhe.h"

mpz_class ::DiffieHellman::set_peer_pubkey(mpz_class pub_key) {
    K_ = Util::powm(pub_key, x_, p_);
    return K_;
}