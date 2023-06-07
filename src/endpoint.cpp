#include "endpoint.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>
}

#include <cstddef>
#include <optional>
#include <uvw.hpp>

#include "connection.hpp"
#include "handler.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Endpoint::Endpoint(std::shared_ptr<Handler>& quic_manager)
    {
        handler = quic_manager;

        expiry_timer = get_loop()->resource<uvw::TimerHandle>();
        expiry_timer->on<uvw::TimerEvent>([this](const auto&, auto&) { check_timeouts(); });
        expiry_timer->start(250ms, 250ms);

        log::info(log_cat, "Successfully created QUIC endpoint");
    };

    // Endpoint::~Endpoint()
    // {
    //     log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    //     shutdown();

    //     if (expiry_timer)
    //         expiry_timer->close();
    // }

    // adds async_cb to all connections; intended use is async shutdown of connections
    void Endpoint::call_async_all(async_callback_t async_cb)
    {
        for (const auto& c : conns)
            c.second->io_trigger->on<uvw::AsyncEvent>(async_cb);

        // for (const auto& c : conns)
        //     c.second->io_ready();
    }

    void Endpoint::close_conns()
    {
        for (const auto& c : conns)
        {
            close_connection(*c.second.get());
        }
    }

    std::shared_ptr<uvw::Loop> Endpoint::get_loop()
    {
        return (handler->ev_loop) ? handler->ev_loop : nullptr;
    }

    void Endpoint::handle_packet(Packet& pkt)
    {
        auto dcid_opt = handle_initial_packet(pkt);

        if (!dcid_opt)
        {
            log::warning(log_cat, "Error: initial packet handling failed");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        log::debug(log_cat, "Incoming connection ID: {}", *dcid.data);
        auto cptr = get_conn(dcid);

        if (!cptr)
        {
            cptr = accept_initial_connection(pkt, dcid);

            if (!cptr)
            {
                log::warning(log_cat, "Error: connection could not be created");
                return;
            }
        }

        handle_conn_packet(*cptr, pkt);
        return;
    }

    void Endpoint::close_connection(Connection& conn, int code, std::string_view msg)
    {
        log::debug(log_cat, "Closing connection (CID: {})", *conn.source_cid.data);

        if (!conn || conn.closing || conn.draining)
            return;

        if (code == NGTCP2_ERR_IDLE_CLOSE)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now without close "
                    "packet",
                    *conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now with close packet",
                    *conn.source_cid.data);
        }

        ngtcp2_connection_close_error err;
        ngtcp2_connection_close_error_set_transport_error_liberr(
                &err, code, reinterpret_cast<uint8_t*>(const_cast<char*>(msg.data())), msg.size());

        conn.conn_buffer.resize(max_pkt_size_v4);
        Path path;
        ngtcp2_pkt_info pkt_info;

        auto written = ngtcp2_conn_write_connection_close(
                conn, path, &pkt_info, u8data(conn.conn_buffer), conn.conn_buffer.size(), &err, get_timestamp());

        if (written <= 0)
        {
            log::warning(
                    log_cat,
                    "Error: Failed to write connection close packet: {}",
                    (written < 0) ? strerror(written) : "[Error Unknown: closing pkt is 0 bytes?]"s);

            delete_connection(conn.source_cid);
            return;
        }
        // ensure we have enough write space
        assert(written <= (long)conn.conn_buffer.size());

        if (auto rv = send_packet(conn.path, conn.conn_buffer); rv.failure())
        {
            log::warning(
                    log_cat,
                    "Error: failed to send close packet [code: {}]; removing connection [CID: {}]",
                    rv.str(),
                    *conn.source_cid.data);
            delete_connection(conn.source_cid);
        }
    }

    void Endpoint::delete_connection(const ConnectionID& cid)
    {
        auto target = conns.find(cid);
        if (target == conns.end())
        {
            log::warning(log_cat, "Error: could not delete connection [ID: {}]; could not find", *cid.data);
            return;
        }

        auto c_ptr = target->second.get();

        if (c_ptr->on_closing)
        {
            c_ptr->on_closing(*c_ptr);
            c_ptr->on_closing = nullptr;
        }

        conns.erase(target);
    }

    std::optional<ConnectionID> Endpoint::handle_initial_packet(Packet& pkt)
    {
        ngtcp2_version_cid vid;
        auto rv = ngtcp2_pkt_decode_version_cid(&vid, u8data(pkt.data), pkt.data.size(), NGTCP2_MAX_CIDLEN);

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {  // version negotiation has not been sent yet, ignore packet
            send_version_negotiation(vid, pkt.path);
            return std::nullopt;
        }
        if (rv != 0)
        {
            log::debug(log_cat, "Error: failed to decode QUIC packet header [code: {}]", ngtcp2_strerror(rv));
            return std::nullopt;
        }

        if (vid.dcidlen > NGTCP2_MAX_CIDLEN)
        {
            log::debug(log_cat, "Error: destination ID is longer than NGTCP2_MAX_CIDLEN");
            return std::nullopt;
        }

        return std::make_optional<ConnectionID>(vid.dcid, vid.dcidlen);
    }

    void Endpoint::handle_conn_packet(Connection& conn, Packet& pkt)
    {
        if (auto rv = ngtcp2_conn_is_in_closing_period(conn); rv != 0)
        {
            log::debug(
                    log_cat, "Error: connection (CID: {}) is in closing period; dropping connection", *conn.source_cid.data);
            delete_connection(conn.source_cid);
            return;
        }

        if (conn.draining)
        {
            log::debug(log_cat, "Error: connection is already draining; dropping");
        }

        if (read_packet(conn, pkt).success())
            log::trace(log_cat, "done with incoming packet");
        else
            log::trace(log_cat, "read packet failed"); // error will be already logged
    }

    io_result Endpoint::read_packet(Connection& conn, Packet& pkt)
    {
        auto rv = ngtcp2_conn_read_pkt(conn, pkt.path, &pkt.pkt_info, u8data(pkt.data), pkt.data.size(), get_timestamp());

        switch (rv)
        {
            case 0:
                conn.io_ready();
                break;
            case NGTCP2_ERR_DRAINING:
                log::debug(log_cat, "Draining connection {}", *conn.source_cid.data);
                break;
            case NGTCP2_ERR_PROTO:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                close_connection(conn, rv, "ERR_PROTO"sv);
                break;
            case NGTCP2_ERR_DROP_CONN:
                // drop connection without calling ngtcp2_conn_write_connection_close()
                log::debug(log_cat, "Dropping connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                delete_connection(conn.source_cid);
                break;
            case NGTCP2_ERR_CRYPTO:
                // drop conn without calling ngtcp2_conn_write_connection_close()
                log::debug(
                        log_cat,
                        "Dropping connection {} due to error {} (code: {})",
                        *conn.source_cid.data,
                        ngtcp2_conn_get_tls_alert(conn),
                        ngtcp2_strerror(rv));
                delete_connection(conn.source_cid);
                break;
            default:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.source_cid.data, ngtcp2_strerror(rv));
                close_connection(conn, rv, ngtcp2_strerror(rv));
                break;
        }

        return {rv};
    }

    // We support different compilation modes for trying different methods of UDP sending by setting
    // these defines:
    //
    // OXEN_LIBQUIC_LIBUV_UDP_QUEUING -- does everything through udp_send, which involves setting up
    // packet queuing.  This is not the default because, in practice, it's slower than just sending
    // directly.
    //
    // OXEN_LIBQUIC_UDP_NO_SENDMMSG -- when defined (and not using queuing, above) we always use libuv's
    // try_send, even when on a platform (Linux, FreeBSD) that supports sendmmsg multi-packet sending.
    // By default we use sendmmsg when available.

#ifdef OXEN_LIBQUIC_LIBUV_UDP_QUEUING
    namespace
    {
        struct packet_storage
        {
            int refs = 0;
            std::vector<char> data;
            std::array<uv_udp_send_t, batch_size> send_req;
        };
        void release(packet_storage* storage)
        {
            if (--storage->refs == 0)
                delete storage;
        }
        extern "C" void packet_storage_release(uv_udp_send_t* send, int code)
        {
            release(static_cast<packet_storage*>(send->data));
        }
    }  // namespace
#endif

    io_result Endpoint::send_packets(Path& p, send_buffer_t& buf, size_t n_pkts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        auto handle = get_handle(p);
        assert(handle != nullptr);

        log::trace(log_cat, "Sending {} UDP packets to {}:{}...", n_pkts, p.remote.ip, p.remote.port);

#ifdef OXEN_LIBQUIC_LIBUV_UDP_QUEUING
        // Avoid allocations by each packet by doing just one allocation for the whole batch with a
        // crude reference counter so that we destruct it once when the full batch of packets is
        // sent.  This also requires us to go through raw libuv because uvw insists on owning a
        // complete buffer for each packet.
        auto packet_data = new packet_storage{};
        size_t agg_size = 0;
        for (int i = 0; i < n_pkts; i++)
            agg_size += buf[i].second;
        packet_data->data.resize(agg_size);
        packet_data->refs = n_pkts;

        char* packet_data_pos = packet_data->data.data();
#ifndef NDEBUG
        const char* const packet_data_expected_end = packet_data_pos + agg_size;
#endif
        packet_data->refs++;  // Hold an extra reference to prevent destruction before we return

        // send_req.data = packet_data.release();
        for (int i = 0; i < n_pkts; ++i)
        {
            assert(buf[i].second > 0);

            std::memcpy(packet_data_pos, buf[i].first.data(), buf[i].second);
            uv_buf_t uv_buf;
            uv_buf.base = packet_data_pos;
            uv_buf.len = buf[i].second;
            packet_data_pos += buf[i].second;
            packet_data->refs++;

#ifndef NDEBUG
            buf[i].second = 0;
#endif

            auto* send_req = &packet_data->send_req[i];
            send_req->data = packet_data;

            auto rv = uv_udp_send(send_req, raw_handle, &uv_buf, 1, p.remote, packet_storage_release);
            if (rv != 0)  // This is a libuv error, *not* a udp send error, so we have to clean up
            {
                release(packet_data);  // Delete our outer extra reference
                release(packet_data);  // Delete the reference for this packet
                return io_result{rv};
            }
        }
        assert(packet_data_pos == packet_data_expected_end);

        // Delete our overarching outer extra reference
        release(packet_data);

        return io_result{0};

#elif !defined(OXEN_LIBQUIC_UDP_NO_SENDMMSG) && (defined(__linux__) || defined(__FreeBSD__))
        auto fd = handle->fd();

        std::array<iovec, batch_size> iov;
        std::array<mmsghdr, batch_size> msgs{};
        for (int i = 0; i < n_pkts; i++)
        {
            assert(buf[i].second > 0);

            iov[i].iov_base = buf[i].first.data();
            iov[i].iov_len = buf[i].second;

#ifndef NDEBUG
            buf[i].second = 0;
#endif

            auto& hdr = msgs[i].msg_hdr;
            hdr.msg_iov = &iov[i];
            hdr.msg_iovlen = 1;
            hdr.msg_name = const_cast<sockaddr*>(static_cast<const sockaddr*>(p.remote));
            hdr.msg_namelen = p.remote.sockaddr_size();
        }

        int rv;
        do
        {
            rv = sendmmsg(fd, msgs.data(), n_pkts, 0);
        } while (rv == -1 && errno == EINTR);

        io_result ret{rv == -1 ? errno : 0};

        if (ret.failure())
            log::error(log_cat, "Error sending packet to {}: {}", p.remote.to_string(), ret.str());

        return ret;

#else  // No sendmmsg; just do a series of try_send calls

        for (int i = 0; i < n_pkts; ++i)
        {
            assert(buf[i].second > 0);

            auto rv = handle->trySend(
                    p.remote, const_cast<char*>(reinterpret_cast<const char*>(buf[i].first.data())), buf[i].second);

            assert(rv < 0 || rv == buf[i].second);

#ifndef NDEBUG
            buf[i].second = 0;
#endif

            if (rv < 0)
            {
                log::error(log_cat, "Error {} sending packet to {}", rv, p.remote.to_string());
                return io_result{rv};
            }
        }

        return io_result{0};
#endif
    }

    io_result Endpoint::send_packet(Path& p, bstring_view data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto handle = get_handle(p);

        assert(handle != nullptr);

        log::info(log_cat, "Sending udp to {}:{}...", p.remote.ip.c_str(), p.remote.port);
        handle->send(p.remote, const_cast<char*>(reinterpret_cast<const char*>(data.data())), data.length());

        return io_result{0};
    }

    void Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, Path& p)
    {
        auto randgen = make_mt19937();
        std::array<std::byte, max_pkt_size_v4> _buf;
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto nwrite = ngtcp2_pkt_write_version_negotiation(
                u8data(_buf),
                _buf.size(),
                std::uniform_int_distribution<uint8_t>()(randgen),
                vid.dcid,
                vid.dcidlen,
                vid.scid,
                vid.scidlen,
                versions.data(),
                versions.size());
        if (nwrite <= 0)
        {
            log::warning(log_cat, "Error: Failed to construct version negotiation packet: {}", ngtcp2_strerror(nwrite));
            return;
        }

        send_packet(p, bstring_view{_buf.data(), static_cast<size_t>(nwrite)});
    }

    void Endpoint::check_timeouts()
    {
        auto now = get_timestamp();

        while (!draining.empty() && draining.front().second < now)
        {
            if (auto it = conns.find(draining.front().first); it != conns.end())
            {
                log::debug(log_cat, "Deleting connection {}", *it->first.data);
                conns.erase(it);
            }
            draining.pop();
        }
    }

    Connection* Endpoint::get_conn(ConnectionID ID)
    {
        auto it = conns.find(ID);

        if (it == conns.end())
            return nullptr;

        return it->second.get();
    }
}  // namespace oxen::quic
