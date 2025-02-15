/*
    Test server binary
*/

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    bool no_hash = false;
    cli.add_flag(
            "-H,--no-hash",
            no_hash,
            "Disable data hashing (just use a simple xor byte checksum instead).  Can make a difference on extremely low "
            "latency (e.g. localhost) connections.  Should be specified on the client as well.");
    bool no_checksum = false;
    cli.add_flag(
            "-X,--no-checksum",
            no_checksum,
            "Disable even the simple xor byte checksum (typically used together with -H).  Should be specified on the "
            "client as well.");

    try
    {
        cli.parse(argc, argv);
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

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct stream_info
    {
        explicit stream_info(uint64_t expected) : expected{expected} { gnutls_hash_init(&hasher, GNUTLS_DIG_SHA3_256); }

        ~stream_info() { gnutls_hash_deinit(hasher, nullptr); }

        uint64_t expected;
        uint64_t received = 0;
        unsigned char checksum = 0;
        gnutls_hash_hd_t hasher;
    };

    std::map<ConnectionID, std::map<int64_t, stream_info>> csd;

    stream_data_callback stream_data = [&](Stream& s, bspan data) {
        auto& sd = csd[s.reference_id];

        auto it = sd.find(s.stream_id());
        if (it == sd.end())
        {
            if (data.size() < sizeof(uint64_t))
            {
                log::critical(test_cat, "Well this was unexpected: I got {} < 8 bytes", data.size());
                return;
            }

            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            data = data.subspan(sizeof(uint64_t));

            it = sd.emplace(s.stream_id(), size).first;
            log::warning(test_cat, "First data from new stream {}, expecting {}B!", s.stream_id(), size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;
        info.received += data.size();
        if (info.received > info.expected)
        {
            log::critical(test_cat, "Received too much data ({}B > {}B)!", info.received, info.expected);
            if (!need_more)
                return;
            data = data.first(data.size() - (info.received + info.expected));
        }

        if (!no_checksum)
        {
            uint64_t csum = 0;
            const uint64_t* stuff = reinterpret_cast<const uint64_t*>(data.data());
            for (size_t i = 0; i < data.size() / 8; i++)
                csum ^= stuff[i];
            for (int i = 0; i < 8; i++)
                info.checksum ^= reinterpret_cast<const uint8_t*>(&csum)[i];
            for (size_t i = (data.size() / 8) * 8; i < data.size(); i++)
                info.checksum ^= static_cast<uint8_t>(data[i]);
        }

        if (!no_hash)
            gnutls_hash(info.hasher, reinterpret_cast<const unsigned char*>(data.data()), data.size());

        if (info.received >= info.expected)
        {
            std::vector<unsigned char> final_hash(33);
            gnutls_hash_output(info.hasher, final_hash.data());
            final_hash[32] = info.checksum;

            log::warning(
                    test_cat,
                    "Data from stream {} complete ({} B).  Final hash: {}",
                    s.stream_id(),
                    info.received,
                    oxenc::to_hex(final_hash.begin(), final_hash.end()));

            s.send(std::move(final_hash));
        }
    };

    try
    {
        log::debug(test_cat, "Starting up endpoint");
        auto _server = server_net.endpoint(server_local);
        _server->listen(server_tls, stream_opened, stream_data);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    {
        // We always want to see this log statement because it contains the pubkey the client needs,
        // but it feels wrong to force it to a critical statement, so temporarily lower the level to
        // info to display it.
        log_level_lowerer enable_info{log::Level::info, test_cat.name};
        std::vector<std::string> flags;
        if (server_local != Address{"127.0.0.1", 5500})
            flags.push_back("--remote {}"_format(server_local.to_string()));
        flags.push_back("--remote-pubkey={}"_format(oxenc::to_base64(pubkey)));
        if (no_hash)
            flags.push_back(no_checksum ? "-HX" : "-H");
        else if (no_checksum)
            flags.push_back("-X");

        log::info(
                test_cat,
                "Listening on {}; client connection args:\n\t{}",
                server_local,
                "{}"_format(fmt::join(flags, " ")));
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
