/*
    Test client binary
*/

#include <sodium/crypto_generichash_blake2b.h>

#include <CLI/Validators.hpp>
#include <chrono>
#include <future>
#include <quic.hpp>
#include <random>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

constexpr size_t operator""_kiB(unsigned long long int x)
{
    return x * 1024;
}
constexpr size_t operator""_MiB(unsigned long long int x)
{
    return x * 1024 * 1_kiB;
}
constexpr size_t operator""_GiB(unsigned long long int x)
{
    return x * 1024 * 1_MiB;
}

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test client"};

    std::string remote_addr = "127.0.0.1:5500";
    cli.add_option("--remote", remote_addr, "Remove address to connect to")->type_name("IP:PORT")->capture_default_str();

    std::string local_addr = "";
    cli.add_option("--local", local_addr, "Local bind address, if required")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_cert{"./servercert.pem"};
    cli.add_option("-c,--servercert", server_cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    size_t parallel = 1;
    cli.add_option("-j,--parallel", parallel, "Number of simultaneous streams to send (currently max 32)")
            ->check(CLI::Range(1, 32));

    bool receive = false;
    cli.add_option(
            "-R,--receive",
            receive,
            "If specified receive data from the server instead than sending data.  Ignored if --bidir is specified.");

    bool bidir = false;
    cli.add_option("-B,--bidir", bidir, "Test transfer *and* receiving; if omitted only send or receive (see --receive)");

    uint64_t size = 1'000'000'000;
    cli.add_option(
            "-S,--size",
            size,
            "Amount of data to transfer (if using --bidir, this amount is in each direction).  When using --parallel the "
            "data is divided equally across streams.");

    size_t chunk_size = 64_kiB, chunk_num = 2;
    cli.add_option("--stream-chunk-size", chunk_size, "How much data to queue at once, per chunk");
    cli.add_option("--stream-chunks", chunk_num, "How much chunks to queue at once per stream")->check(CLI::Range(1, 100));

    size_t rng_seed = 0;
    cli.add_option(
            "--rng-seed",
            rng_seed,
            "RNG seed to use for data generation; with --parallel we use this, this+1, ... for the different threads.");

    // TODO: make this optional
    std::string cert{"./clientcert.pem"}, key{"./clientkey.pem"};
    cli.add_option("-C,--certificate", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-K,--key", key, "Path to client key to use for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network client_net{};

    opt::client_tls client_tls{key, cert, server_cert};

    opt::local_addr client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = opt::local_addr{a, p};
    }

    auto [server_a, server_p] = parse_addr(remote_addr);
    opt::remote_addr server_addr{server_a, server_p};

    log::debug(test_cat, "Calling 'client_connect'...");
    auto client = client_net.client_connect(client_local, server_addr, client_tls);

    auto [ev_thread, running, done] = spawn_event_loop(client_net);

    // wait for event loop to start
    running.get();

    auto started_at = std::chrono::steady_clock::now();

    struct stream_data
    {
        std::shared_ptr<Stream> stream;
        size_t remaining;
        std::mt19937 rng;
        std::vector<std::vector<std::byte>> bufs;
        size_t next_buf = 0;
        crypto_generichash_blake2b_state sent_hasher, recv_hasher;

        stream_data() {}
        stream_data(size_t total_size, uint64_t seed, size_t chunk_size, size_t chunk_num) : remaining{total_size}, rng{seed}
        {
            bufs.resize(chunk_num);
            for (auto& buf : bufs)
                buf.resize(chunk_size);
            crypto_generichash_blake2b_init(&sent_hasher, nullptr, 0, 32);
            crypto_generichash_blake2b_init(&recv_hasher, nullptr, 0, 32);
        }
    };

    std::unordered_set<size_t> streams_done;
    std::mutex streams_done_mutex;

    std::vector<stream_data> streams;
    streams.reserve(parallel);

    auto stream_opened = [&](Stream& s) {
        size_t i = s.stream_id << 2;
        log::critical(test_cat, "Stream {} (rawid={}) started", i, s.stream_id);
    };
    auto stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id << 2;
        log::critical(test_cat, "Stream {} (rawid={}) closed (error={})", i, s.stream_id, errcode);
    };

    auto per_stream = size / parallel;

    for (int i = 0; i < parallel; i++)
    {
        auto& s = streams.emplace_back(per_stream + (i == 0 ? size % parallel : 0), rng_seed + i, chunk_size, chunk_num);
        s.stream = client->open_stream(
                [](Stream& s, bstring_view data) {
                    log::warning(test_cat, "received stream data on stream {}", s.stream_id);
                },
                stream_closed);
        s.stream->send_chunks(
                [&, i](const Stream&) -> std::vector<std::byte>* {
                    auto& sd = streams[i];
                    auto& data = sd.bufs[sd.next_buf++];
                    sd.next_buf %= sd.bufs.size();

                    // We generate data 64-bits at a time, so round up our chunk size to the next multiple of 8
                    const auto size = std::min(sd.remaining, chunk_size);
                    if (size == 0)
                        return nullptr;
                    using rng_value = decltype(sd.rng)::result_type;
                    constexpr size_t rng_size = sizeof(rng_value);
                    const size_t rng_chunks = (size + rng_size - 1) / rng_size;
                    const size_t size_data = rng_chunks * rng_size;

                    // Generate some deterministic data from our rng; we're cheating a little here
                    // with the RNG output value (which means this test won't be the same on
                    // different endian machines).
                    data.resize(size_data);
                    auto* rng_data = reinterpret_cast<rng_value*>(data.data());
                    for (size_t i = 0; i < rng_chunks; i++)
                        rng_data[i] = static_cast<rng_value>(sd.rng());
                    data.resize(size);

                    // Hash it (so that we can verify the hash response at the end)
                    crypto_generichash_blake2b_update(
                            &sd.sent_hasher, reinterpret_cast<unsigned char*>(data.data()), data.size());

                    sd.remaining -= size;

                    return &data;
                },
                [&, i](Stream& s) {
                    std::lock_guard lock{streams_done_mutex};
                    auto [it, ins] = streams_done.insert(i);
                    if (!ins)
                        throw std::runtime_error{"Error: got stream done twice for stream " + fmt::to_string(i)};
                },
                chunk_num);
    }

    while (done.wait_for(20ms) != std::future_status::ready)
    {
        std::lock_guard lock{streams_done_mutex};
        if (streams_done.size() >= parallel)
        {
            log::critical(test_cat, "all done!");
            break;
        }
        else
        {
            log::info(test_cat, "waiting...");
        }
    }

    auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
    fmt::print("Elapsed time: {:.3f}s\n", elapsed);
    fmt::print("Speed: {:.3f}MB/s\n", size / 1'000'000.0 / elapsed);

    client_net.ev_loop->stop();
    ev_thread.join();

    return 0;
}
