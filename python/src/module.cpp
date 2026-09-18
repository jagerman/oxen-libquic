#include <oxen/quic/version.hpp>

#include <pybind11/pybind11.h>

#include <string>

namespace py = pybind11;

PYBIND11_MODULE(_core, m)
{
    m.doc() = "Compiled core of the seshquic package; import seshquic instead of this.";

    const auto& v = oxen::quic::VERSION;
    m.attr("__version__") = std::to_string(v[0]) + '.' + std::to_string(v[1]) + '.' + std::to_string(v[2]);
}
