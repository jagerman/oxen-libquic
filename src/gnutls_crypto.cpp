#include "gnutls_crypto.hpp"

#include "internal.hpp"
#include "udp.hpp"

namespace oxen::quic
{
    gtls_reset_token::gtls_reset_token(const uint8_t* t, const uint8_t* r)
    {
        std::memcpy(_tok.data(), t, gtls_reset_token::TOKENSIZE);
        if (r)
            std::memcpy(_rand.data(), r, gtls_reset_token::RANDSIZE);
        else
            generate_rand(_rand.data());
    }

    gtls_reset_token::gtls_reset_token(uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid)
    {
        generate_token(_tok.data(), _static_secret, _secret_len, cid);
        generate_rand(_rand.data());
    }

    void gtls_reset_token::generate_token(uint8_t* buffer, uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid)
    {
        if (ngtcp2_crypto_generate_stateless_reset_token(buffer, _static_secret, _secret_len, &cid) != 0)
            throw std::runtime_error{"Failed to generate stateless reset token!"};
    }

    void gtls_reset_token::generate_rand(uint8_t* buffer)
    {
        if (gnutls_rnd(GNUTLS_RND_RANDOM, buffer, RANDSIZE) != 0)
            throw std::runtime_error{"Failed to generate stateless reset random"};
    }

    std::shared_ptr<gtls_reset_token> gtls_reset_token::generate(
            uint8_t* _static_secret, size_t _secret_len, const quic_cid& cid)
    {
        std::shared_ptr<gtls_reset_token> ret = nullptr;
        try
        {
            ret = std::shared_ptr<gtls_reset_token>{new gtls_reset_token{_static_secret, _secret_len, cid}};
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "gtls_reset_token exception: {}", e.what());
        }

        return ret;
    }

    std::shared_ptr<gtls_reset_token> gtls_reset_token::make_copy(const uint8_t* t, const uint8_t* r)
    {
        return std::shared_ptr<gtls_reset_token>{new gtls_reset_token{t, r}};
    }

    std::shared_ptr<gtls_reset_token> gtls_reset_token::parse_packet(const Packet& pkt)
    {
        return gtls_reset_token::make_copy(pkt.data<uint8_t>(pkt.size() - gtls_reset_token::TOKENSIZE).data());
    }
}  //  namespace oxen::quic
