#include "stream.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
}

#include <cstddef>
#include <cstdio>
#include <stdexcept>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
#include "network.hpp"
#include "types.hpp"

namespace oxen::quic
{
    Stream::Stream(Connection& conn, Endpoint& _ep, stream_data_callback data_cb, stream_close_callback close_cb) :
            IOChannel{conn, _ep},
            reference_id{conn.reference_id()},
            data_callback{data_cb},
            close_callback{std::move(close_cb)}
    {
        log::trace(log_cat, "Creating Stream object...");

        if (!data_callback)
            data_callback = conn.get_default_data_callback();

        if (!close_callback)
            close_callback = [](Stream&, uint64_t error_code) {
                log::info(log_cat, "Default stream close callback called ({})", quic_strerror(error_code));
            };

        log::trace(log_cat, "Stream object created");
    }

    Stream::~Stream()
    {
        log::trace(log_cat, "Destroying stream {}", _stream_id);
    }

    bool Stream::available() const
    {
        return endpoint.call_get([this] { return !(_is_closing || _is_shutdown || _sent_fin); });
    }

    bool Stream::is_ready() const
    {
        return endpoint.call_get([this] { return _ready; });
    }

    std::shared_ptr<Stream> Stream::get_stream()
    {
        return shared_from_this();
    }

    void Stream::close(uint64_t app_err_code)
    {
        if (app_err_code > APP_ERRCODE_MAX)
            throw std::invalid_argument{"Invalid application error code (too large)"};

        // NB: this *must* be a call (not a call_soon) because Connection calls on a short-lived
        // Stream that won't survive a return to the event loop.
        endpoint.call([this, app_err_code]() {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (_is_shutdown)
                log::info(log_cat, "Stream is already shutting down");
            else if (_is_closing)
                log::debug(log_cat, "Stream is already closing");
            else
            {
                _is_closing = _is_shutdown = true;
                if (_conn)
                {
                    log::info(log_cat, "Closing stream (ID: {}) with: {}", _stream_id, quic_strerror(app_err_code));
                    ngtcp2_conn_shutdown_stream(*_conn, 0, _stream_id, app_err_code);
                }
            }
            if (_is_shutdown)
                data_callback = nullptr;

            if (!_conn)
            {
                log::warning(log_cat, "Stream close ignored: the stream's connection is gone");
                return;
            }

            _conn->packet_io_ready();
        });
    }

    void Stream::closed(uint64_t app_code)
    {
        if (close_callback)
        {
            try
            {
                close_callback(*this, app_code);
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception in stream close callback: {}", e.what());
            }
        }

        _conn = nullptr;
        _is_closing = _is_shutdown = true;
    }

    void Stream::append_buffer(bstring_view buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        user_buffers.emplace_back(buffer, std::move(keep_alive));
        assert(endpoint.in_event_loop());
        assert(_conn);
        if (_ready)
            _conn->packet_io_ready();
        else
            log::info(log_cat, "Stream not ready for broadcast yet, data appended to buffer and on deck");
    }

    void Stream::acknowledge(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Acking {} bytes of {}/{} unacked/size", bytes, _unacked_size, size());

        assert(bytes <= _unacked_size);
        _unacked_size -= bytes;

        // drop all acked user_buffers, as they are unneeded
        while (bytes >= user_buffers.front().first.size() && bytes)
        {
            bytes -= user_buffers.front().first.size();
            user_buffers.pop_front();
            log::trace(log_cat, "bytes: {}", bytes);
        }

        // advance bsv pointer to cover any remaining acked data
        if (bytes)
            user_buffers.front().first.remove_prefix(bytes);

        log::trace(log_cat, "{} bytes acked, {} unacked remaining", bytes, size());
    }

    void Stream::wrote(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Increasing _unacked_size by {}B", bytes);
        _unacked_size += bytes;
    }

    static auto get_buffer_it(std::deque<std::pair<bstring_view, std::shared_ptr<void>>>& bufs, size_t offset)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto it = bufs.begin();

        while (offset >= it->first.size() && it != bufs.end() && offset)
        {
            offset -= it->first.size();
            it++;
        }

        return std::make_pair(std::move(it), offset);
    }

    std::vector<ngtcp2_vec> Stream::pending()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::vector<ngtcp2_vec> nbufs{};

        log::trace(log_cat, "unsent: {}", unsent());

        if (user_buffers.empty() || unsent() == 0)
            return nbufs;

        auto [it, offset] = get_buffer_it(user_buffers, _unacked_size);
        nbufs.reserve(std::distance(it, user_buffers.end()));
        auto& temp = nbufs.emplace_back();
        temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data() + offset));
        temp.len = it->first.size() - offset;
        while (++it != user_buffers.end())
        {
            auto& temp = nbufs.emplace_back();
            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(it->first.data()));
            temp.len = it->first.size();
        }

        return nbufs;
    }

    void Stream::send_impl(bstring_view data, std::shared_ptr<void> keep_alive)
    {
        if (data.empty())
            return;

        // If we aren't currently in the event loop then we need to keep a weak pointer to the
        // stream so that, when the below lambda gets processed, we can tell whether the stream is
        // still actually alive.  (But if we're already in the event loop the lambda fires
        // immediately and we don't want to have to do an extra refcount increment/decrement).
        std::optional<std::weak_ptr<Stream>> wself;
        if (!endpoint.in_event_loop())
            wself = weak_from_this();

        // In theory, `endpoint` that we use here might be inaccessible as well, but unlike conn
        // (which we have to check because it could have been closed by remote actions or network
        // events) the application has control and responsibility for keeping the network/endpoint
        // alive at least as long as all the Connections/Streams that instances that were attached
        // to it.
        endpoint.call([this, wself = std::move(wself), data, ka = std::move(keep_alive)]() {
            std::shared_ptr<Stream> sself;
            if (wself)
            {
                // send() was called from outside the event loop, so check to make sure the stream
                // is still alive (and thus `this` is still valid):
                if (!(sself = wself->lock()))
                {
                    log::debug(log_cat, "Stream has gone away, dropping send data");
                    return;
                }
            }
            // else send() was already inside the event loop and thus `this` is still valid

            if (_is_closing || _is_shutdown || _sent_fin)
            {
                log::debug(log_cat, "Stream {} is closing/shutting down, dropping send data", _stream_id);
                return;
            }
            else if (!_conn || _conn->is_closing() || _conn->is_draining())
            {
                log::debug(log_cat, "Stream {} unable to send: connection is closed", _stream_id);
                return;
            }
            log::trace(log_cat, "Stream (ID: {}) sending message: {}", _stream_id, buffer_printer{data});
            append_buffer(data, std::move(ka));
        });
    }

    size_t Stream::unsent_impl() const
    {
        log::trace(log_cat, "size={}, unacked={}", size(), unacked());
        return size() - unacked();
    }

    void Stream::set_ready()
    {
        log::trace(log_cat, "Setting stream ready");
        _ready = true;
        on_ready();
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message)
    {
        log::trace(log_cat, "{}:{} -- {}", file, lineno, message);
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val)
    {
        log::trace(log_cat, "{}:{} -- {}{}", file, lineno, message, val);
    }

    prepared_datagram Stream::pending_datagram(bool)
    {
        log::warning(log_cat, "{} called, but this is a stream object!", __PRETTY_FUNCTION__);
        throw std::runtime_error{"Stream objects should not be queried for pending datagrams!"};
    }

}  // namespace oxen::quic
