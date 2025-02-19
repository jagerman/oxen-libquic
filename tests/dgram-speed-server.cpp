/*
    Test server binary
*/

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC datagram speedtest server"};

    auto server_addr = DEFAULT_DGRAM_SPEED_ADDR.to_string();
    std::string seed_string;
    bool enable_0rtt;
    common_server_opts(cli, server_addr, seed_string, enable_0rtt);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        server_tls->enable_inbound_0rtt();

    Network server_net{};

    auto [listen_addr, listen_port] = parse_addr(server_addr, DEFAULT_DGRAM_SPEED_ADDR.port());
    Address server_local{listen_addr, listen_port};

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct recv_info
    {
        uint64_t n_expected = 0;
        uint64_t n_received = 0;
    };

    recv_info dgram_data;

    std::promise<void> t_prom;
    std::future<void> t_fut = t_prom.get_future();

    std::shared_ptr<Endpoint> server;

    dgram_data_callback recv_dgram_cb = [&](dgram_interface& di, std::vector<std::byte> data) {
        if (dgram_data.n_expected == 0)
        {
            // The very first packet should be 8 bytes containing the uint64_t count of total
            // packets being sent, not including this initial one.
            if (data.size() != 8)
                log::error(test_cat, "Invalid initial packet: expected 8-byte test size, got {} bytes", data.size());
            auto count = oxenc::load_little_to_host<uint64_t>(data.data());
            dgram_data.n_expected = count;
            log::warning(
                    test_cat,
                    "First data from new connection datagram channel, expecting {} datagrams!",
                    dgram_data.n_expected);
            return;
        }

        // Subsequent packets start with a \x00 until the final one; that has first byte set to \x01.
        const bool done = data[0] != std::byte{0};

        auto& info = dgram_data;
        bool need_more = info.n_received < info.n_expected;
        info.n_received += 1;

        if (info.n_received > info.n_expected)
        {
            log::critical(test_cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);

            if (!need_more)
                return;
        }

        if (done)
        {
            auto reception_rate = ((float)info.n_received / (float)info.n_expected) * 100;

            log::critical(
                    test_cat,
                    "Datagram test complete. Fidelity: {}\% ({} received of {} expected)",
                    reception_rate,
                    info.n_received,
                    info.n_expected);

            di.reply("DONE!"s);
            t_prom.set_value();
        }
    };

    try
    {
        log::debug(test_cat, "Starting up endpoint");
        auto split_dgram = opt::enable_datagrams(Splitting::ACTIVE);
        // opt::enable_datagrams split_dgram(Splitting::ACTIVE);
        server = server_net.endpoint(
                server_local, recv_dgram_cb, split_dgram, generate_static_secret(seed_string), opt::alpns{"dgram-speed"});
        server->listen(server_tls, stream_opened);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    server_log_listening(server_local, DEFAULT_DGRAM_SPEED_ADDR, pubkey, seed_string, enable_0rtt);

    t_fut.get();

    log::warning(test_cat, "Shutting down test server");
}
