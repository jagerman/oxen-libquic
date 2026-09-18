#pragma once

#include <pybind11/pybind11.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace seshquic
{
    namespace py = pybind11;

    /// Releases the GIL for the duration of the scope, but only if this thread is actually holding
    /// it.  pybind11's gil_scoped_release asserts ownership, and these helpers are reachable both
    /// from Python calls (GIL held) and from libquic's event loop thread (usually not), as well as
    /// nested inside each other during destruction.
    class gil_release
    {
        std::optional<py::gil_scoped_release> _release;

      public:
        gil_release()
        {
            if (PyGILState_Check())
                _release.emplace();
        }
    };

    /// Owns a libquic object on Python's behalf.
    ///
    /// Endpoints, connections and streams are created with deleters that dispatch destruction to
    /// the event loop thread and block until it finishes.  Python drops its last reference at an
    /// arbitrary point with the GIL held -- during garbage collection, say -- and that block would
    /// then deadlock against the loop thread waiting for the GIL to run a callback.  So the GIL
    /// goes away before the reference does.
    ///
    /// The same applies to anything else that waits on the loop, which is why the wrappers below
    /// call into libquic through `without_gil` rather than holding it across the call.
    template <typename T>
    class loop_owned
    {
        std::shared_ptr<T> _ptr;

      public:
        loop_owned() = default;
        explicit loop_owned(std::shared_ptr<T> ptr) : _ptr{std::move(ptr)} {}

        loop_owned(const loop_owned&) = delete;
        loop_owned& operator=(const loop_owned&) = delete;
        loop_owned(loop_owned&&) = default;
        loop_owned& operator=(loop_owned&&) = default;

        ~loop_owned() { reset(); }

        void reset()
        {
            if (!_ptr)
                return;
            gil_release unlock;
            _ptr.reset();
        }

        const std::shared_ptr<T>& ptr() const { return _ptr; }
        T* get() const { return _ptr.get(); }
        T* operator->() const { return _ptr.get(); }
        T& operator*() const { return *_ptr; }
        explicit operator bool() const { return static_cast<bool>(_ptr); }
    };

    /// Invokes `f` with the GIL released.  Every call into libquic goes through this: most of its
    /// accessors dispatch to the event loop thread and block for the result, which deadlocks
    /// against a loop thread trying to acquire the GIL for a callback.
    template <typename F>
    decltype(auto) without_gil(F&& f)
    {
        gil_release unlock;
        return std::forward<F>(f)();
    }

    /// Copies a Python bytes-like object (anything supporting the buffer protocol: bytes,
    /// bytearray, memoryview, array) into owned storage.
    ///
    /// Callers get a copy rather than a view because libquic holds onto send buffers past the call,
    /// and a Python buffer can be mutated or freed in the meantime.  `str` is deliberately not
    /// accepted: the caller picks the encoding, as they do for a socket.
    std::vector<std::byte> to_bytes(const py::object& obj);

    /// Copies data into a new Python `bytes`.  Views handed to callbacks are only valid for the
    /// duration of the callback, so there is nothing to be gained by trying to avoid the copy.
    inline py::bytes from_bytes(std::span<const std::byte> data)
    {
        return py::bytes{reinterpret_cast<const char*>(data.data()), data.size()};
    }

    inline py::bytes from_bytes(std::span<const unsigned char> data)
    {
        return py::bytes{reinterpret_cast<const char*>(data.data()), data.size()};
    }

    void init_address(py::module_& m);
    void init_creds(py::module_& m);

}  // namespace seshquic
