#pragma once

#include "common.hpp"

#include <oxen/quic/connection.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/stream.hpp>

#include <pybind11/pybind11.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace seshquic
{
    using oxen::quic::Connection;
    using oxen::quic::Endpoint;
    using oxen::quic::Loop;
    using oxen::quic::Stream;

    /// Holds a Python callable that libquic will invoke from its event loop thread.
    ///
    /// Calling a Python object needs the GIL, and so does *destroying* one; this is destroyed on
    /// the loop thread when the stream or connection holding it goes away, so it owns that detail
    /// rather than leaving it to each call site.  Copyability is required because libquic stores
    /// these in std::function, which is copy-constructible.
    class py_callback
    {
        py::object _fn;

      public:
        py_callback() = default;

        explicit py_callback(py::object fn)
        {
            if (fn && !fn.is_none())
                _fn = std::move(fn);
        }

        py_callback(const py_callback& other)
        {
            if (other._fn)
            {
                py::gil_scoped_acquire gil;
                _fn = other._fn;
            }
        }

        py_callback(py_callback&&) noexcept = default;

        py_callback& operator=(const py_callback& other)
        {
            if (this != &other)
            {
                py::gil_scoped_acquire gil;
                _fn = other._fn;
            }
            return *this;
        }

        py_callback& operator=(py_callback&&) noexcept = default;

        ~py_callback()
        {
            if (!_fn)
                return;

            if (python_is_finalizing())
            {
                // Releasing the reference needs the GIL, which this thread will never be given
                // again.  Deliberately leak it instead: the interpreter is going away and taking
                // the whole heap with it, whereas hanging here would wedge the process at exit.
                _fn.release();
                return;
            }

            py::gil_scoped_acquire gil;
            py::object dying = std::move(_fn);
        }

        explicit operator bool() const { return static_cast<bool>(_fn); }

        /// Invokes the callback with the GIL held.
        ///
        /// Exceptions do not propagate: this sits on libquic's callback stack, which runs through
        /// ngtcp2's C callbacks, so letting one escape would terminate the process.  A Python
        /// exception is reported through sys.unraisablehook instead, which is where an exception
        /// from a thread that nobody can catch belongs.
        ///
        /// Callers that build Python arguments must hold the GIL themselves while doing so;
        /// acquiring it again here is cheap and reentrant.
        template <typename... Args>
        void operator()(Args&&... args) const
        {
            if (!_fn || python_is_finalizing())
                return;

            py::gil_scoped_acquire gil;
            try
            {
                _fn(std::forward<Args>(args)...);
            }
            catch (py::error_already_set& e)
            {
                e.discard_as_unraisable(_fn);
            }
        }
    };

    /// An event loop, which runs on its own thread.
    ///
    /// Only worth holding directly in order to share one between endpoints; an Endpoint given no
    /// loop makes its own.
    class PyLoop
    {
        std::shared_ptr<Loop> _loop{std::make_shared<Loop>()};

      public:
        PyLoop() = default;
        PyLoop(const PyLoop&) = delete;
        PyLoop& operator=(const PyLoop&) = delete;

        ~PyLoop()
        {
            gil_release unlock;
            _loop.reset();
        }

        const std::shared_ptr<Loop>& loop() const { return _loop; }
    };

    class PyStream
    {
        observed<Stream> _s;

      public:
        explicit PyStream(const std::shared_ptr<Stream>& s) : _s{s} {}

        /// The stream, or a raised Python exception if its connection has gone away.
        std::shared_ptr<Stream> get() const;
        const observed<Stream>& handle() const { return _s; }

        void send(const py::object& data);
        void send_fin();
        void close(uint64_t error_code);

        void set_data_callback(py::object cb);
        void set_close_callback(py::object cb);
        void set_fin_callback(py::object cb);
    };

    class PyConnection
    {
        observed<Connection> _c;

      public:
        explicit PyConnection(const std::shared_ptr<Connection>& c) : _c{c} {}

        /// The connection, or a raised Python exception if its endpoint has gone away.
        std::shared_ptr<Connection> get() const;
        const observed<Connection>& handle() const { return _c; }

        py::object open_stream(py::object on_data, py::object on_close, py::object on_fin);
        void close(uint64_t error_code);
    };

    class PyEndpoint
    {
        // Declared first so that it outlives the endpoint: libquic requires the loop to stay alive
        // for the endpoint's lifetime, and does not itself hold a reference.
        std::shared_ptr<Loop> _loop;
        loop_owned<Endpoint> _ep;

      public:
        PyEndpoint(
                const py::object& local,
                PyLoop* loop,
                std::optional<std::vector<std::string>> alpns,
                std::optional<double> handshake_timeout,
                std::optional<size_t> max_udp_payload,
                bool allow_gso,
                py::object on_connection,
                py::object on_connection_closed);

        Endpoint& get() const;

        void listen(
                std::shared_ptr<oxen::quic::TLSCreds> creds,
                py::object on_connection,
                py::object on_connection_closed,
                py::object on_stream_data,
                py::object on_stream_close,
                py::object on_stream_fin);

        py::object connect(
                const py::object& remote,
                const py::object& remote_pubkey,
                std::shared_ptr<oxen::quic::TLSCreds> creds,
                std::optional<std::vector<std::string>> alpns,
                std::optional<double> idle_timeout,
                std::optional<double> keep_alive,
                std::optional<double> handshake_timeout,
                py::object on_connection,
                py::object on_connection_closed,
                py::object on_stream_data,
                py::object on_stream_close,
                py::object on_stream_fin);

        void close(double wait);
    };

    /// Wraps a libquic object in a fresh Python object.  The GIL must be held.
    ///
    /// Each call makes a new Python object referring to the same underlying stream or connection,
    /// so identity is not preserved across callbacks; equality and hashing are.
    py::object wrap(const std::shared_ptr<Stream>& s);
    py::object wrap(const std::shared_ptr<Connection>& c);

    /// As above, from the reference a libquic callback is handed.
    py::object wrap_stream(Stream& s);
    py::object wrap_connection(Connection& c);

    /// Builds the libquic callbacks that dispatch into Python.  Each returns an empty function when
    /// given None, so that libquic falls back to its own defaults.
    oxen::quic::stream_data_callback make_stream_data_cb(py::object cb);
    oxen::quic::stream_close_callback make_stream_close_cb(py::object cb);
    oxen::quic::opt::stream_fin_callback make_stream_fin_cb(py::object cb);
    oxen::quic::connection_established_callback make_conn_established_cb(py::object cb);
    oxen::quic::connection_closed_callback make_conn_closed_cb(py::object cb);

    /// Builds an `opt::` option from a duration in seconds, as Python expresses one, or nothing at
    /// all if the argument was omitted.  libquic's option handling skips an empty optional, which
    /// is what lets its variadic interfaces be driven by keyword arguments.
    template <typename Option, typename Duration>
    std::optional<Option> duration_option(std::optional<double> seconds)
    {
        if (!seconds)
            return std::nullopt;
        return Option{std::chrono::duration_cast<Duration>(std::chrono::duration<double>{*seconds})};
    }

    void init_endpoint(py::module_& m);
    void init_stream(py::module_& m);

}  // namespace seshquic
