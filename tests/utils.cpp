#include "utils.hpp"

#include <nettle/eddsa.h>
#include <nettle/sha3.h>

namespace oxen::quic
{
    void TestHelper::migrate_connection(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        auto rv = ngtcp2_conn_initiate_migration(conn, conn._path, get_timestamp().count());
        log::trace(test_cat, "{}", ngtcp2_strerror(rv));
    }

    void TestHelper::migrate_connection_immediate(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        auto rv = ngtcp2_conn_initiate_immediate_migration(conn, conn._path, get_timestamp().count());
        log::trace(test_cat, "{}", ngtcp2_strerror(rv));
    }

    void TestHelper::nat_rebinding(Connection& conn, Address new_bind)
    {
        auto& current_sock = const_cast<std::unique_ptr<UDPSocket>&>(conn._endpoint.get_socket());
        auto new_sock = std::make_unique<UDPSocket>(conn._endpoint.get_loop().get(), new_bind, [&](auto&& packet) {
            conn._endpoint.handle_packet(std::move(packet));
        });

        auto& new_addr = new_sock->address();
        Path new_path{new_addr, conn._path.remote};

        conn.set_local_addr(new_addr);
        conn._endpoint.set_local(new_addr);

        current_sock.swap(new_sock);
        ngtcp2_conn_set_local_addr(conn, &new_addr._addr);
    }

    Connection* TestHelper::get_conn(std::shared_ptr<Endpoint>& ep, std::shared_ptr<connection_interface>& _conn)
    {
        auto* conn = static_cast<Connection*>(_conn.get());
        return ep->get_conn(conn->_source_cid);
    }

    UDPSocket::socket_t TestHelper::get_sock(Endpoint& ep)
    {
        return ep.get_socket()->sock_;
    }

    void TestHelper::enable_dgram_drop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_counter_enabled = false;
            conn.debug_datagram_drop_enabled = true;
            conn.debug_datagram_counter = 0;
        });
    }
    int TestHelper::disable_dgram_drop(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] {
            conn.debug_datagram_drop_enabled = false;
            int count = 0;
            std::swap(count, conn.debug_datagram_counter);
            return count;
        });
    }
    void TestHelper::enable_dgram_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        conn._endpoint.call_get([&conn] {
            conn.debug_datagram_drop_enabled = false;
            conn.debug_datagram_counter_enabled = true;
            conn.debug_datagram_counter = 0;
        });
    }
    int TestHelper::disable_dgram_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] {
            conn.debug_datagram_counter_enabled = false;
            int count = 0;
            std::swap(count, conn.debug_datagram_counter);
            return count;
        });
    }
    int TestHelper::get_dgram_debug_counter(connection_interface& ci)
    {
        auto& conn = static_cast<Connection&>(ci);
        return conn._endpoint.call_get([&conn] { return conn.debug_datagram_counter; });
    }

    void TestHelper::increment_ref_id(Endpoint& ep, uint64_t by)
    {
        ep._next_rid += by;
    }

    std::pair<std::shared_ptr<GNUTLSCreds>, std::shared_ptr<GNUTLSCreds>> test::defaults::tls_creds_from_ed_keys()
    {
        auto client = GNUTLSCreds::make_from_ed_keys(CLIENT_SEED, CLIENT_PUBKEY);
        auto server = GNUTLSCreds::make_from_ed_keys(SERVER_SEED, SERVER_PUBKEY);

        return std::make_pair(std::move(client), std::move(server));
    }

    void sha3_256(uint8_t* out, std::span<const uint8_t> value, std::string_view domain)
    {
        sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        if (!domain.empty())
            sha3_256_update(&ctx, domain.size(), reinterpret_cast<const uint8_t*>(domain.data()));

        sha3_256_update(&ctx, value.size(), value.data());
        sha3_256_digest(&ctx, 32, out);
    }
    void sha3_256(uint8_t* out, std::span<const char> value, std::string_view domain)
    {
        return sha3_256(out, {reinterpret_cast<const uint8_t*>(value.data()), value.size()}, domain);
    }
    void sha3_512(uint8_t* out, std::span<const uint8_t> value, std::string_view domain)
    {
        sha3_512_ctx ctx;
        sha3_512_init(&ctx);
        if (!domain.empty())
            sha3_512_update(&ctx, domain.size(), reinterpret_cast<const uint8_t*>(domain.data()));

        sha3_512_update(&ctx, value.size(), value.data());
        sha3_512_digest(&ctx, 32, out);
    }
    void sha3_512(uint8_t* out, std::span<const char> value, std::string_view domain)
    {
        return sha3_512(out, {reinterpret_cast<const uint8_t*>(value.data()), value.size()}, domain);
    }

    std::pair<std::string, std::string> generate_ed25519(std::string_view seed_string)
    {

        std::pair<std::string, std::string> result;
        auto& [seed, pubkey] = result;
        seed.resize(32);

        if (!seed_string.empty())
        {
            log::info(test_cat, "Generating insecure but reproducible keys from seed string '{}'", seed_string);
            sha3_256(reinterpret_cast<uint8_t*>(seed.data()), seed_string, "libquic-test-ed25519-generator");
        }
        else
        {
            gnutls_rnd(gnutls_rnd_level_t::GNUTLS_RND_KEY, seed.data(), sizeof(seed.size()));
        }

        pubkey.resize(32);
        ed25519_sha512_public_key(
                reinterpret_cast<unsigned char*>(pubkey.data()), reinterpret_cast<const unsigned char*>(seed.data()));

        return result;
    }

    void add_log_opts(CLI::App& cli, std::string& file, std::string& level)
    {
        file = "stderr";
        level = "info";

        cli.add_option("-l,--log-file", file, "Log output filename, or one of stdout/-/stderr/syslog.")
                ->type_name("FILE")
                ->capture_default_str();

        cli.add_option("-L,--log-level", level, "Log verbosity level; one of trace, debug, info, warn, error, critical, off")
                ->type_name("LEVEL")
                ->capture_default_str()
                ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "critical", "off"}));
    }

    void setup_logging(std::string out, const std::string& level)
    {
        log::Level lvl = log::level_from_string(level);

        constexpr std::array print_vals = {"stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
        log::Type type;
        if (std::count(print_vals.begin(), print_vals.end(), out))
            type = log::Type::Print;
        else if (out == "syslog")
            type = log::Type::System;
        else
            type = log::Type::File;

        oxen::log::add_sink(type, out, "[%T.%f] [%*] [\x1b[1m%n\x1b[0m:%^%l%$|\x1b[3m%g:%#\x1b[0m] %v");
        oxen::log::reset_level(lvl);

        if (lvl <= oxen::log::Level::trace)
            enable_gnutls_logging();
    }

    std::string friendly_duration(std::chrono::nanoseconds dur)
    {
        std::string friendly;
        auto append = std::back_inserter(friendly);
        bool some = false;
        if (dur >= 24h)
        {
            fmt::format_to(append, "{}d", dur / 24h);
            dur %= 24h;
            some = true;
        }
        if (dur >= 1h || some)
        {
            fmt::format_to(append, "{}h", dur / 1h);
            dur %= 1h;
            some = true;
        }
        if (dur >= 1min || some)
        {
            fmt::format_to(append, "{}m", dur / 1min);
            dur %= 1min;
            some = true;
        }
        if (some || dur % 1s == 0ns)
        {
            // If we have >= minutes or its an integer number of seconds then don't bother with
            // fractional seconds
            fmt::format_to(append, "{}s", dur / 1s);
        }
        else
        {
            double seconds = std::chrono::duration<double>(dur).count();
            if (dur >= 1s)
                fmt::format_to(append, "{:.3f}s", seconds);
            else if (dur >= 1ms)
                fmt::format_to(append, "{:.3f}ms", seconds * 1000);
            else if (dur >= 1us)
                fmt::format_to(append, "{:.3f}µs", seconds * 1'000'000);
            else
                fmt::format_to(append, "{:.0f}ns", seconds * 1'000'000'000);
        }
        return friendly;
    }

}  // namespace oxen::quic
