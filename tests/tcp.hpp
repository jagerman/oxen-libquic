#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
}

#include "utils.hpp"

namespace oxen::quic
{
    struct TCPConnection;
    class TCPListener;

    inline const auto LOCALHOST = "127.0.0.1"s;
    inline constexpr auto TUNNEL_SEED = "0000000000000000000000000000000000000000000000000000000000000000"_hex;
    inline constexpr auto TUNNEL_PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"_hex;

    inline constexpr size_t HIGH_WATERMARK{4_Mi};
    inline constexpr size_t LOW_WATERMARK{HIGH_WATERMARK / 2};

    inline constexpr size_t TCP_HIGHWATER{2_Mi};
    inline constexpr size_t TCP_LOWWATER{TCP_HIGHWATER / 2};

    inline std::vector<std::byte> serialize_payload(bstring_view data, uint16_t port = 0)
    {
        std::vector<std::byte> ret(data.size() + sizeof(port));
        std::memcpy(ret.data(), data.data(), data.size());
        oxenc::write_host_as_big(port, ret.data() + data.size());
        return ret;
    }

    inline uint16_t deserialize_payload(bstring& data)
    {
        if (data.size() < 2)
            throw std::invalid_argument{"Not a valid payload"};
        uint16_t p = oxenc::load_big_to_host<uint16_t>(data.data() + data.size() - 2);
        data.resize(data.size() - 2);
        return p;
    }

    // Properly updates an Address from a fd by calling `get_name(fd, ...)` on it; typically
    // get_name is either getsockname or getpeername.
    inline void update_addr(Address& a, evutil_socket_t fd, decltype(&getsockname) get_name)
    {
        socklen_t len = sizeof(sockaddr);
        if (get_name(fd, a, &len) < 0)
            throw std::runtime_error{"Failed to retrieve socket address: {}"_format(strerror(errno))};
        a.update_socklen(len);
    }

    struct TCPQUIC
    {
        std::shared_ptr<connection_interface> ci;

        // keyed against backend tcp address
        std::unordered_map<Address, std::unordered_set<std::shared_ptr<TCPConnection>>> tcp_conns;
    };

    // held in a map keyed against the remote address
    struct tunneled_connection
    {
        // Listener (optional)
        std::shared_ptr<TCPListener> listener;

        // keyed against the remote port (for tunnel_client) or local port (for tunnel_server)
        std::unordered_map<uint16_t, TCPQUIC> conns;
    };

    inline constexpr auto evconnlistener_deleter = [](::evconnlistener* e) {
        log::trace(test_cat, "Invoking evconnlistener deleter!");
        if (e)
            evconnlistener_free(e);
    };

    // Helper class that helps us manage lifetime of an evbuffer that may have multiple chunks in
    // it; we directly reference the data contained within, and then drain the evbuffer on
    // destruction (so that we can use this as the keep-alive for a stream send).  Additionally,
    // when we drain the final chunk, we free the evbuffer itself.
    //
    // The intention here is to allow you to get an evbuffer and supply its sub-buffers as stream
    // data, using this deleter to clean up the underlying evbuffer data apprpriately as the data
    // gets acked on the stream.
    //
    // Note that this requires that the buffer data is processed and destructed in order (which will
    // be the case for data sent into a single stream).
    struct partial_ev_buffer
    {
        evbuffer* buf;
        const size_t len;
        partial_ev_buffer(evbuffer* buf, size_t len) : buf{buf}, len{len} {}
        ~partial_ev_buffer()
        {
            evbuffer_drain(buf, len);
            if (evbuffer_get_contiguous_space(buf) == 0)
                evbuffer_free(buf);
        }
    };

    struct TCPConnection
    {
      public:
        // Constructor for creating a new, outgoing TCP connection
        TCPConnection(std::shared_ptr<Loop> _ev, std::shared_ptr<Stream> _s, Address _addr) :
                stream{std::move(_s)}, ev{std::move(_ev)}, raddr{std::move(_addr)}
        {
            bev = bufferevent_socket_new(ev->loop().get(), -1, BEV_OPT_CLOSE_ON_FREE);
            if (bufferevent_socket_connect(bev, raddr, raddr.socklen()))
                throw std::runtime_error{"Failed to initialize TCP connection"};

            init();

            log::info(
                    test_cat,
                    "TCP tunneled connection initialized to {} (local addr {}) for stream {}",
                    raddr,
                    laddr,
                    stream->stream_id());
        }

        // Constructor for taking over an existing open TCP connection, typically just after
        // accepting the connection.
        TCPConnection(std::shared_ptr<Loop> _ev, std::shared_ptr<Stream> _s, evutil_socket_t fd) :
                stream{std::move(_s)}, ev{std::move(_ev)}
        {
            bev = bufferevent_socket_new(ev->loop().get(), fd, BEV_OPT_CLOSE_ON_FREE);

            update_addr(raddr, fd, getpeername);

            init();

            log::info(
                    test_cat,
                    "TCP tunneled connection accepted from {} (local addr {}) for stream {}",
                    raddr,
                    laddr,
                    stream->stream_id());
        }

        TCPConnection() = delete;

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection()
        {
            if (bev)
            {
                log::debug(test_cat, "TCPConnection destructor fired with a still-open TCP socket; closing it");
                ev->call([this] {
                    bufferevent_free(bev);
                    bev = nullptr;
                });
            }
        }

        const std::shared_ptr<Stream> stream;
        const Address& remote_addr() const { return raddr; }
        const Address& local_addr() const { return laddr; }
        bool expect_initial_magic = true;

      private:
        std::shared_ptr<Loop> ev;
        struct bufferevent* bev;
        Address laddr, raddr;

        void init()
        {
            try
            {
                auto fd = bufferevent_getfd(bev);
                update_addr(laddr, fd, getsockname);
                set_tcp_callbacks();
                initialize_stream_callbacks();
                bufferevent_enable(bev, EV_READ | EV_WRITE);
            }
            catch (...)
            {
                // If something throws, intercept it and free the bufferevent (because we're still
                // in the constructor, and so the destructor won't fire to free bev when we throw
                // from here).
                bufferevent_free(bev);
                bev = nullptr;
                throw;
            }
        }

        void handle_stream_data(oxen::quic::Stream& s, bstring_view data)
        {
            if (expect_initial_magic)
            {
                expect_initial_magic = false;
                assert(!data.empty());
                if (data[0] != std::byte{0x42})
                    s.close(42);
                data.remove_prefix(1);
                if (data.empty())
                    return;
            }

            auto sz = data.size();

            if (!bev)
                throw std::runtime_error{"Stream (id: {}) has no socket to write {}B to!"_format(s.stream_id(), sz)};

            auto rv = bufferevent_write(bev, data.data(), data.size());
            log::trace(
                    test_cat,
                    "Stream (id: {}) {} {}B to TCP output buffer!",
                    rv < 0 ? "failed to write" : "successfully wrote",
                    s.stream_id(),
                    sz);

            // If we've received data on the stream faster than the tcp socket can accept
            // the data (and thus have a large output buffer on the socket) then we need to
            // pause the stream so that the far side will stop sending.  (This isn't
            // immediate: there is still several MB more that may be coming our way in the
            // current allowed-data window before the far side can't send any more).
            if (evbuffer_get_length(bufferevent_get_output(bev)) >= TCP_HIGHWATER and not s.is_paused())
            {
                log::info(test_cat, "TCP output buffer over high-water threshold ({}); pausing stream...", TCP_HIGHWATER);

                // Pause the stream and set the drained callback and low watermark so that
                // as soon as we drop below TCP_LOWWATER, the drained callback fires to
                // resume the stream.
                s.pause();
                set_tcp_callbacks(tcp_drained_cb);
                bufferevent_setwatermark(bev, EV_WRITE, TCP_LOWWATER, 0);
            }
        }

        void initialize_stream_callbacks()
        {
            stream->set_stream_data_cb([this](oxen::quic::Stream& s, bstring_view data) { handle_stream_data(s, data); });

            stream->set_stream_close_cb([this](Stream&, uint64_t) {
                log::critical(
                        test_cat,
                        "Stream closed cb fired, {}...",
                        bev ? "freeing bufferevent" : "bufferevent already freed");
                assert(bev);
                bufferevent_free(bev);
                bev = nullptr;
            });

            auto on_stream_reset = [this](Stream&, uint64_t) {
                if (!bev)
                    return;

                // The other side has indicate that it is no longer sending us data, so we
                // need to let the tcp buffer finish writing anything currently in its
                // buffer, and then shut it down when the buffer is emptied.  (Or if there's
                // nothing in the buffer, shut it down immediately).
                if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
                {
                    set_tcp_callbacks(tcp_write_done_cb);
                    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
                }
                else
                    tcp_write_done_cb();
            };

            stream->set_remote_reset_hooks(opt::remote_stream_reset{nullptr, std::move(on_stream_reset)});

            // If we get too much (HIGH_WATERMARK) unacked (or unsent) data sitting on the stream
            // then we pause reading from the tcp socket until it has been acked down to
            // LOW_WATERMARK so that we limit the max size of data sitting in our stream buffer.
            stream->set_watermark(
                    LOW_WATERMARK,
                    HIGH_WATERMARK,
                    opt::watermark{[this](Stream&) {
                        log::debug(test_cat, "Stream buffer below low-water threshold; enabling TCP read!");
                        bufferevent_enable(bev, EV_READ);
                    }},
                    opt::watermark{[this](Stream&) {
                        log::debug(test_cat, "Stream buffer above high-water threshold; disabling TCP read!");
                        bufferevent_disable(bev, EV_READ);
                    }});
        }

        // Sets the read and event callbacks to their normal values, and sets the write callback
        // (which is the only one we ever change) to the given callback.
        void set_tcp_callbacks(void (*write_cb)(bufferevent*, void*) = nullptr)
        {
            bufferevent_setcb(bev, tcp_read_cb, write_cb, tcp_event_cb, this);
        }

        static void tcp_read_cb(bufferevent*, void* self) { static_cast<TCPConnection*>(self)->tcp_read_cb(); }
        static void tcp_event_cb(bufferevent*, short what, void* self)
        {
            static_cast<TCPConnection*>(self)->tcp_event_cb(what);
        }
        static void tcp_drained_cb(bufferevent*, void* self) { static_cast<TCPConnection*>(self)->tcp_drained_cb(); }
        static void tcp_write_done_cb(bufferevent*, void* self) { static_cast<TCPConnection*>(self)->tcp_write_done_cb(); }

        void tcp_read_cb()
        {
            auto* buf = evbuffer_new();
            if (bufferevent_read_buffer(bev, buf) == 0)
            {
                assert(evbuffer_get_length(buf) > 0);
                log::trace(
                        test_cat, "TCP socket received {}B for stream ID {}", evbuffer_get_length(buf), stream->stream_id());

                std::vector<evbuffer_iovec> iovs;
                iovs.resize(evbuffer_peek(buf, -1, nullptr, nullptr, 0));
                evbuffer_peek(buf, -1, nullptr, iovs.data(), iovs.size());
                for (const auto& iov : iovs)
                {
                    stream->send(
                            bstring_view{static_cast<std::byte*>(iov.iov_base), iov.iov_len},
                            std::make_shared<partial_ev_buffer>(buf, iov.iov_len));
                }
            }
            else
            {
                log::error(test_cat, "TCP socket has no pending data in input buffer; why did we get a read callback?");
            }
        }

        void tcp_event_cb(short what)
        {
            if (what & BEV_EVENT_CONNECTED)
            {
                log::info(test_cat, "TCP connection established for stream {}", stream->stream_id());
                return;
            }

            if (what & BEV_EVENT_ERROR)
            {
                int errcode = EVUTIL_SOCKET_ERROR();
                log::error(
                        test_cat,
                        "TCP connection encountered uncoverable error ({}); closing stream {}",
                        evutil_socket_error_to_string(errcode),
                        stream->stream_id());
                stream->close(errcode);

                bufferevent_free(bev);
                bev = nullptr;

                return;
            }

            if (what & BEV_EVENT_EOF)
            {
                bool write_eof = what & BEV_EVENT_WRITING;
                bool read_eof = what & BEV_EVENT_READING;
                if (write_eof && read_eof)
                {
                    log::info(test_cat, "Backend TCP stopped reading and writing; closing stream", stream->stream_id());
                    stream->stop_sending();
                }
                else if (write_eof)
                {
                    log::info(
                            test_cat,
                            "Backend TCP stopped reading! Telling stream {} remote to stop sending",
                            stream->stream_id());
                    stream->stop_sending();
                }
                else
                {
                    assert(what & BEV_EVENT_READING);
                    log::info(
                            test_cat,
                            "Backend TCP stopped reading! Telling stream {} remote to stop sending",
                            stream->stream_id());
                    stream->reset_stream();
                }
            }
        }

        // This callback is set up when we have an overfilled tcp write buffer and have paused
        // the stream to stop the flow of incoming data; the callback itself is invoked once we
        // should reenable the stream because we have cleared enough of the output buffer.
        void tcp_drained_cb()
        {
            log::info(
                    test_cat,
                    "TCP output buffer is below low-water threshold ({}); resuming stream {}",
                    TCP_LOWWATER,
                    stream->stream_id());

            set_tcp_callbacks();
            bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

            stream->resume();
        }

        // Called when the other side has indicated it is no longer writing *and* we have no
        // more output buffer left, so we should shutdown writing on the tcp socket.
        void tcp_write_done_cb()
        {
            assert(evbuffer_get_length(bufferevent_get_output(bev)) == 0);

            log::info(
                    test_cat,
                    "TCP output buffer drained for read-stopped stream {}; shutting down tcp socket write",
                    stream->stream_id());

            shutdown(bufferevent_getfd(bev), SHUT_WR);

            set_tcp_callbacks();
        }
    };

    // Callback that conn_accepted gets called with: we *pass* this callback to conn_accepted, which
    // calls it with a connection on which we can open a new stream to associate with the TCP
    // connection, then put wire everything up into a TCPConnection and return that.  (Or, if it
    // doesn't get called, we abort the connection after the callback returns).
    using make_tcp_stream = std::function<std::shared_ptr<TCPConnection>(connection_interface&)>;
    using conn_accepted_callback = std::function<void(make_tcp_stream)>;

    class TCPListener
    {
        std::shared_ptr<Loop> _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        Address _addr;

        conn_accepted_callback _conn_accepted;

      public:
        TCPListener(const std::shared_ptr<Loop>& ev, conn_accepted_callback accept_cb, uint16_t p = 0) :
                _ev{ev}, _addr{LOCALHOST, p}, _conn_accepted{std::move(accept_cb)}
        {
            if (!_ev || !_conn_accepted)
                throw std::invalid_argument{"TCPSocket construction requires non-empty ev/stream_cb/accept_cb"};

            init();
        }

        // returns the bound address of the TCP listener
        const Address& local_addr() const { return _addr; }

      private:
        void init()
        {
            _tcp_listener = _ev->shared_ptr<struct evconnlistener>(
                    evconnlistener_new_bind(
                            _ev->loop().get(), tcp_accept_cb, this, LEV_OPT_CLOSE_ON_FREE, -1, _addr, _addr.socklen()),
                    evconnlistener_deleter);

            if (not _tcp_listener)
                throw std::runtime_error{
                        "TCP listener construction failed: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            update_addr(_addr, evconnlistener_get_fd(_tcp_listener.get()), getsockname);

            evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);
        }

        static void tcp_accept_cb(evconnlistener*, evutil_socket_t fd, sockaddr*, int, void* self)
        {
            static_cast<TCPListener*>(self)->tcp_accept_cb(fd);
        }
        void tcp_accept_cb(evutil_socket_t fd)
        {
            bool called = false;
            auto tcp_construct = [this, &fd, &called](connection_interface& conn) {
                auto s = conn.open_stream();
                // We were connected to, so need to make sure the remote establishes a connection,
                // which it does on stream creation.  However, QUIC streams are lazy, so there won't
                // be a stream opened event until some actual data comes down the stream.  Thus we
                // always prime it here by sending a single 0x42 byte down it to make sure it opens
                // even if there isn't any immediate data to send.
                auto c = std::make_shared<TCPConnection>(_ev, std::move(s), fd);
                c->expect_initial_magic = false;
                c->stream->send("\x42"sv);

                called = true;
                return c;
            };
            try
            {
                _conn_accepted(tcp_construct);
            }
            catch (const std::exception& e)
            {
                log::warning(test_cat, "TCP accept callback raised an exception: {}", e.what());
            }
            if (!called)
            {
                log::error(test_cat, "TCP accept callback did not invoke the construction callback; aborting connection");
                evutil_closesocket(fd);
            }
        }

        static void tcp_err_cb(struct evconnlistener*, void*)
        {
            int ec = EVUTIL_SOCKET_ERROR();
            log::critical(test_cat, "TCP LISTENER RECEIVED ERROR CODE {}: {}", ec, evutil_socket_error_to_string(ec));

            // DISCUSS: close everything here?
        }
    };

}  //  namespace oxen::quic
