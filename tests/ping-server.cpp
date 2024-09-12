/*
    Ping server binary
*/

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC ping server"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    bool no_verify = false;
    cli.add_flag(
            "-V,--no-verify", no_verify, "Disable key verification on incoming connections (cannot be disabled with 0-RTT)");

    bool enable_0rtt = false;
    cli.add_flag(
            "-Z,--enable-0rtt",
            enable_0rtt,
            "Enable 0-RTT and early data for this endpoint (cannot be used without key verification)");

    try
    {
        cli.parse(argc, argv);

        if (no_verify and enable_0rtt)
            throw std::invalid_argument{"0-RTT must be used with key verification!"};
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto [seed, pubkey] = generate_ed25519();
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    Network server_net{};

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    Address server_local{listen_addr, listen_port};

    std::shared_ptr<Endpoint> server;

    std::atomic<bool> first_data{false};

    /**     0: connection established
            1: stream opened
            2: recv (first) stream data / close conn
            3: connection closed
     */
    std::array<uint64_t, 4> timing;

    auto conn_established = [&](connection_interface& ci) {
        timing[0] = get_timestamp<std::chrono::milliseconds>().count();
        log::critical(test_cat, "Connection established to {}", ci.remote());
    };

    auto conn_closed = [&](connection_interface& ci, uint64_t) {
        timing[3] = get_timestamp<std::chrono::milliseconds>().count();
        log::critical(test_cat, "Connection closed to {}", ci.remote());

        log::critical(test_cat, "\n\tConnection established: {}.{}ms", timing[0] / 1'000'000, timing[0] % 1000);
        log::critical(test_cat, "\n\tFirst stream opened: {}.{}ms", timing[1] / 1'000'000, timing[1] % 1000);
        log::critical(
                test_cat, "\n\tFirst stream data received/close sent: {}.{}ms", timing[2] / 1'000'000, timing[2] % 1000);
        log::critical(test_cat, "\n\tConnection closed: {}.{}ms", timing[3] / 1'000'000, timing[3] % 1000);

        first_data = false;
    };

    auto stream_opened = [&](Stream& s) {
        timing[1] = get_timestamp<std::chrono::milliseconds>().count();
        log::critical(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    auto stream_recv = [&](Stream& s, bstring_view) {
        // get the time first, then do ops
        auto t = get_timestamp<std::chrono::milliseconds>().count();
        if (not first_data.exchange(true))
        {
            timing[2] = t;
            log::critical(test_cat, "Received first data on connection to {}", s.remote());
            s.send("good afternoon"_bsv);
            server->get_conn(s.reference_id)->close_connection();
        }
    };

    try
    {
        log::info(test_cat, "Starting up endpoint...");
        server = server_net.endpoint(server_local, conn_established, conn_closed);
        server->listen(server_tls, stream_opened, stream_recv);
        log::critical(
                test_cat,
                "Server listening on: {}{}awaiting connections...",
                server_local,
                no_verify ? ", " : " with pubkey: \n\n\t{}\n\n"_format(oxenc::to_base64(pubkey)));
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
