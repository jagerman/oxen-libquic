/*
    Ping client binary
*/

#include "utils.hpp"

using namespace oxen::quic;

constexpr auto client_msg = "good morning"_bsp;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC ping client"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string remote_addr = "127.0.0.1:5500";
    cli.add_option("--remote", remote_addr, "Remove address to connect to")->type_name("IP:PORT")->capture_default_str();

    std::string remote_pubkey;
    cli.add_option("-p,--remote-pubkey", remote_pubkey, "Remote server pubkey (not needed with verification disabled)")
            ->type_name("PUBKEY_HEX_OR_B64")
            ->transform([](const std::string& val) -> std::string {
                if (auto pk = decode_bytes(val))
                    return std::move(*pk);
                throw CLI::ValidationError{
                        "Invalid value passed to --remote-pubkey: expected value encoded as hex or base64"};
            });

    std::string local_addr = "";
    cli.add_option("--local", local_addr, "Local bind address (optional)")->type_name("IP:PORT")->capture_default_str();

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

        if (enable_0rtt and remote_pubkey.empty())
            throw std::invalid_argument{"0-RTT must be used with remote key!"};

        if (not no_verify and remote_pubkey.empty())
            throw std::invalid_argument{"If remote key is provided, key verification must be turned OFF"};
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network client_net{};

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);

    Address client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = Address{a, p};
    }

    std::promise<void> all_done;
    std::atomic<bool> first_data{false};

    /**     0: start connecting
            1: connection established
            2: send data down stream
            3: recv (first) stream response
            4: connection closed
     */
    std::array<uint64_t, 5> timing;

    auto conn_established = [&](connection_interface& ci) {
        timing[1] = get_timestamp<std::chrono::milliseconds>().count();
        log::critical(test_cat, "Connection established to {}", ci.remote());
    };

    auto conn_closed = [&](connection_interface& ci, uint64_t) {
        timing[4] = get_timestamp<std::chrono::milliseconds>().count();
        log::critical(test_cat, "Connection closed to {}", ci.remote());
        all_done.set_value();
    };

    auto stream_recv = [&](Stream& s, bspan) {
        // get the time first, then do ops
        auto t = get_timestamp<std::chrono::milliseconds>().count();
        if (not first_data.exchange(true))
        {
            timing[3] = t;
            log::critical(test_cat, "Received first data on connection to {}", s.remote());
        }
    };

    auto [server_a, server_p] = parse_addr(remote_addr);
    Address server_addr{server_a, server_p};

    log::info(test_cat, "Constructing endpoint on {}", client_local);

    auto client = enable_0rtt
                        ? client_net.endpoint(client_local, conn_established, conn_closed, opt::enable_0rtt_ticketing{})
                        : client_net.endpoint(client_local, conn_established, conn_closed);

    log::info(test_cat, "Connecting to {}...", server_addr);

    timing[0] = get_timestamp<std::chrono::milliseconds>().count();
    auto client_conn = no_verify ? client->connect(server_addr, client_tls, stream_recv, opt::disable_key_verification{})
                                 : client->connect(RemoteAddress{remote_pubkey, server_addr}, stream_recv, client_tls);
    auto client_stream = client_conn->open_stream();
    timing[2] = get_timestamp<std::chrono::milliseconds>().count();
    client_stream->send(client_msg);

    all_done.get_future().wait();

    log::critical(test_cat, "\n\tConnection started: {}.{}ms", timing[0] / 1'000'000, timing[0] % 1000);
    log::critical(test_cat, "\n\tConnection established: {}.{}ms", timing[1] / 1'000'000, timing[1] % 1000);
    log::critical(test_cat, "\n\tFirst stream data sent: {}.{}ms", timing[2] / 1'000'000, timing[2] % 1000);
    log::critical(test_cat, "\n\tFirst stream data received: {}.{}ms", timing[3] / 1'000'000, timing[3] % 1000);
    log::critical(test_cat, "\n\tConnection closed: {}.{}ms", timing[4] / 1'000'000, timing[4] % 1000);
}
