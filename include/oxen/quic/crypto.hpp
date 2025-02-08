#pragma once

extern "C"
{
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <memory>

#include "address.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline constexpr auto default_alpn_str = "default"_usv;
    inline constexpr std::chrono::milliseconds DEFAULT_ANTI_REPLAY_WINDOW{15s};

    class TLSSession;
    class Connection;
    struct IOContext;

    struct session_data
    {
        std::vector<unsigned char> tls_session_ticket;
        std::vector<unsigned char> quic_transport_params;
    };

    class TLSCreds
    {
      public:
        virtual std::unique_ptr<TLSSession> make_session(
                Connection& c,
                const IOContext& ctx,
                const std::vector<ustring>& alpns,
                std::optional<ustring_view> expected_remote_key) = 0;

        // Called when a TLS session ticket is received, to store both that (required for the TLS
        // layer) and the encoded ngtcp2 0-RTT data from the connection (required for the QUIC layer).
        virtual void store_session_ticket(
                Connection& conn, RemoteAddress addr, std::span<const unsigned char> ticket_data) = 0;

        // Extract session data from storage, parses it into the TLS + QUIC layer data needed for
        // 0-RTT.  Returns nullopt if not found.
        virtual std::optional<session_data> extract_session_data(const RemoteAddress& addr) = 0;

        // Returns true if server-side 0-RTT is enabled
        virtual bool inbound_0rtt() const = 0;

        // Returns true if client-side 0-RTT is enabled
        virtual bool outbound_0rtt() const = 0;

        virtual ~TLSCreds() = default;
    };

    class TLSSession
    {
      public:
        ngtcp2_crypto_conn_ref conn_ref;
        virtual void* get_session() = 0;
        virtual bool get_early_data_accepted() const = 0;
        virtual ustring_view selected_alpn() const = 0;
        virtual ustring_view remote_key() const = 0;

        // If this session loaded 0-rtt data, this will return the encoded transport data to be
        // loaded into the ngtcp2 connection to enable 0-RTT.  Note that the value is transferred to
        // the caller by this call, and so this can only (usefully) be called once.
        virtual std::optional<std::vector<unsigned char>> extract_0rtt_tp_data() = 0;

        // Called upon QUIC handshake completion, to send TLS session tickets if needed.
        virtual void send_session_tickets() = 0;

        virtual ~TLSSession() = default;
    };

}  // namespace oxen::quic
