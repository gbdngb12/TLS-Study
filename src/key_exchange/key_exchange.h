namespace tls::key_exchange {

template <typename private_key_type, typename public_key_type, typename shared_key_type>
class KeyExchange {
   public:
    /**
     * @brief 공유 세션키를 가져온다.
     * 
     * @return shared_key_type 공유 세션키
     */
    virtual shared_key_type get_shared_key() const noexcept {
        return m_shared_key;
    }
    virtual ~KeyExchange() = default;
/*
    KeyExchange(const KeyExchange&) = delete;
    KeyExchange& operator=(const KeyExchange&) = delete;

    KeyExchange(const KeyExchange&&) noexcept = default;
    KeyExchange& operator=(const KeyExchange&&) noexcept = default;*/

    /**
     * @brief 상대방의 공개키를 설정한다.
     *
     * @param peer_public_key 상대방의 공개키
     * @return public_key_type 설정한 상대방의 공개키
     */
    virtual public_key_type set_peer_pubkey(public_key_type peer_public_key) noexcept = 0;
    /**
     * @brief 사용자의 공개키를 가져온다
     * 
     * @return public_key_type 공개키
     */
    virtual public_key_type get_public_key() const noexcept {
        return m_public_key;
    }
   protected:
    /**
     * @brief 공유 세션키를 생성한다.
     *
     */
    virtual void set_shared_key() noexcept = 0;
    /**
     * @brief 비밀키
     *
     */
    private_key_type m_private_key;
    /**
     * @brief 공개 상수
     *
     */
    public_key_type m_public_key;
    /**
     * @brief 상대방의 공개키
     *
     */
    public_key_type m_peer_public_key;
    /**
     * @brief 공유 세션키
     *
     */
    shared_key_type m_shared_key;
};
}  // namespace tls::key_exchange