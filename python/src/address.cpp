#include "common.hpp"

#include <oxen/quic/address.hpp>

#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace seshquic
{
    using oxen::quic::Address;

    void init_address(py::module_& m)
    {
        py::class_<Address>{m, "Address", R"(A local or remote socket address.

Constructed from a host string and port; the host may be an IPv4 or IPv6 address, and an empty
host means "any address" (dual stack, where the platform supports it).  `Address.parse` takes the
combined `host:port` or `[v6addr]:port` forms instead.
)"}
                .def(py::init<const std::string&, uint16_t>(), py::arg("host") = "", py::arg("port") = 0)
                .def_static(
                        "parse",
                        [](std::string_view addr, std::optional<uint16_t> default_port) {
                            return Address::parse(addr, default_port);
                        },
                        py::arg("addr"),
                        py::arg("default_port") = py::none(),
                        R"(Parses "host:port", "[v6addr]:port" or a bare host.

A bare host is only accepted when `default_port` is given; otherwise the port is required.
Raises ValueError if the address cannot be parsed.
)")
                .def_property_readonly("host", &Address::host)
                .def_property_readonly("port", &Address::port)
                .def_property_readonly("is_ipv4", &Address::is_ipv4)
                .def_property_readonly("is_ipv6", &Address::is_ipv6)
                .def_property_readonly("is_set", &Address::is_set)
                .def_property_readonly("is_loopback", &Address::is_loopback)
                .def_property_readonly("is_public", &Address::is_public)
                .def_property_readonly("is_any_addr", &Address::is_any_addr)
                .def_property_readonly("is_any_port", &Address::is_any_port)
                .def_property_readonly(
                        "is_addressable",
                        &Address::is_addressable,
                        "True if this names a specific host and port, i.e. is usable as a connect target.")
                .def(py::self == py::self)
                .def(py::self < py::self)
                .def("__hash__", [](const Address& a) { return std::hash<std::string>{}(a.to_string()); })
                .def("__str__", &Address::to_string)
                .def("__repr__", [](const Address& a) { return "Address('" + a.to_string() + "')"; });
    }

}  // namespace seshquic
