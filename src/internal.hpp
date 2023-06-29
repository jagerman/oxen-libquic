#pragma once

#include <cstddef>

#include "utils.hpp"

namespace oxen::quic
{
    namespace log = oxen::log;
    inline auto log_cat = log::Cat("quic");
    using namespace log::literals;

    void logger_config(std::string out = "stderr", log::Type type = log::Type::Print, log::Level reset = log::Level::trace);

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

}  // namespace oxen::quic
