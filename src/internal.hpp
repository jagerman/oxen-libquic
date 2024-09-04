#pragma once

#include <cstddef>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "format.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    namespace log = oxen::log;

    using namespace log::literals;

    void logger_config(std::string out = "stderr", log::Type type = log::Type::Print, log::Level reset = log::Level::trace);

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

    namespace detail
    {
        // Wrapper around inet_pton that throws an exception on error
        inline void parse_addr(int af, void* dest, const std::string& from)
        {
            auto rv = inet_pton(af, from.c_str(), dest);

            if (rv == 0)  // inet_pton returns this on invalid input
                throw std::invalid_argument{"Unable to parse IP address!"};
            if (rv < 0)
                throw std::system_error{errno, std::system_category()};
        }

        // Parses an IPv4 address from string
        inline void parse_addr(in_addr& into, const std::string& from)
        {
            parse_addr(AF_INET, &into.s_addr, from);
        }

        // Parses an IPv6 address from string
        inline void parse_addr(in6_addr& into, const std::string& from)
        {
            parse_addr(AF_INET6, &into, from);
        }
    }  // namespace detail

    struct connection_callbacks
    {
        static int on_ack_datagram(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data);

        static int on_recv_datagram(ngtcp2_conn* conn, uint32_t flags, const uint8_t* data, size_t datalen, void* user_data);

        static int on_recv_token(ngtcp2_conn* conn, const uint8_t* token, size_t tokenlen, void* user_data);

        static int on_recv_stream_data(
                ngtcp2_conn* conn,
                uint32_t flags,
                int64_t stream_id,
                uint64_t offset,
                const uint8_t* data,
                size_t datalen,
                void* user_data,
                void* stream_user_data);

        static int on_acked_stream_data_offset(
                ngtcp2_conn* conn_,
                int64_t stream_id,
                uint64_t offset,
                uint64_t datalen,
                void* user_data,
                void* stream_user_data);

        static int on_stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data);

        static int on_stream_close(
                ngtcp2_conn* conn,
                uint32_t flags,
                int64_t stream_id,
                uint64_t app_error_code,
                void* user_data,
                void* stream_user_data);

        static int on_stream_reset(
                ngtcp2_conn* conn,
                int64_t stream_id,
                uint64_t final_size,
                uint64_t app_error_code,
                void* user_data,
                void* stream_user_data);

        static int on_handshake_completed(ngtcp2_conn*, void* user_data);

        static int on_handshake_confirmed(ngtcp2_conn*, void* user_data);

        static void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);

        static int on_connection_id_status(
                ngtcp2_conn* _conn,
                ngtcp2_connection_id_status_type type,
                uint64_t seq,
                const ngtcp2_cid* cid,
                const uint8_t* token,
                void* user_data);

        static int get_new_connection_id(
                ngtcp2_conn* _conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data);

        static int remove_connection_id(ngtcp2_conn* _conn, const ngtcp2_cid* cid, void* user_data);

        static int extend_max_local_streams_bidi(ngtcp2_conn* _conn, uint64_t max_streams, void* user_data);

        static int on_path_validation(
                ngtcp2_conn* _conn [[maybe_unused]],
                uint32_t flags,
                const ngtcp2_path* path,
                const ngtcp2_path* old_path,
                ngtcp2_path_validation_result res,
                void* user_data);

        static int on_early_data_rejected(ngtcp2_conn* _conn, void* user_data);
    };

    struct gtls_session_callbacks
    {
        static int server_anti_replay_cb(void* dbf, time_t exp_time, const gnutls_datum_t* key, const gnutls_datum_t* data);

        static int client_session_cb(
                gnutls_session_t session,
                unsigned int htype,
                unsigned when,
                unsigned int incoming,
                const gnutls_datum_t* msg);
    };

}  // namespace oxen::quic
