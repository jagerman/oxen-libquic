/*
    Ping server binary
*/

#include "utils.hpp"

#include <oxen/quic/gnutls_crypto.hpp>
#include <oxenc/endian.h>

#include <CLI/Validators.hpp>

#include <gnutls/gnutls.h>

#include <random>

using namespace oxen::quic;

namespace oxen::quic
{
    GNUTLSCreds::anti_replay_add_cb default_anti_replay_add();
}

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC ping server"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    bool enable_0rtt = false;
    cli.add_flag("-Z,--enable-0rtt", enable_0rtt, "Enable 0-RTT and early data for this endpoint");

    std::string seed_string = "";
    cli.add_option(
            "-s,--seed",
            seed_string,
            "If non-empty then the server key and endpoint private data will be generated from a hash of the given seed, "
            "for reproducible keys and operation.  If omitted/empty a random seed is used.");

    double flakiness = 0.0;
    cli.add_option("-f,--flakiness", flakiness, "Fail to respond to pings this proportion of the time.")
            ->capture_default_str()
            ->expected(0.0, 1.0);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    if (seed_string.empty())
    {
        seed_string.resize(32);
        gnutls_rnd(GNUTLS_RND_KEY, seed_string.data(), seed_string.size());
    }

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    Network server_net{};

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    Address server_local{listen_addr, listen_port};

    std::shared_ptr<Endpoint> server;

    auto conn_established = [&](connection_interface& ci) {
        log::info(test_cat, "Incoming connection established from {}", ci.remote());
    };

    auto conn_closed = [&](connection_interface& ci, uint64_t) {
        log::info(test_cat, "Connection from {} closed", ci.remote());
    };

    auto flake = [rng = std::mt19937_64{std::random_device{}()},
                  flake = std::bernoulli_distribution{flakiness},
                  &flakiness]() mutable -> bool { return flakiness > 0 ? flake(rng) : false; };
    auto dgram_recv = [&](dgram_interface& d, std::vector<std::byte> in) {
        if (in.size() != 4)
        {
            log::error(test_cat, "Received invalid ping datagram of size {} (expected 4 bytes); ignoring", in.size());
            return;
        }
        auto ping_num = oxenc::load_little_to_host<uint32_t>(in.data());
        if (flake())
            log::debug(test_cat, "received ping {} but simulating flakiness and not replying", ping_num);
        else
        {
            log::debug(test_cat, "received ping {}, reflecting it", ping_num);
            d.reply(std::move(in));
        }
    };

    std::vector<unsigned char> ep_secret;
    ep_secret.resize(32);
    sha3_256(ep_secret.data(), seed_string, "libquic-test-static-secret");

    try
    {
        log::info(test_cat, "Starting endpoint...");
        if (enable_0rtt)
            server_tls->enable_inbound_0rtt();

        server = server_net.endpoint(
                server_local,
                conn_established,
                conn_closed,
                opt::enable_datagrams{},
                opt::static_secret{std::move(ep_secret)});
        server->listen(server_tls, dgram_recv);
        log::info(
                test_cat,
                "Server listening on: {} with pubkey:\n\n\t{}\n\nawaiting connections...",
                server_local,
                oxenc::to_base64(pubkey));
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
