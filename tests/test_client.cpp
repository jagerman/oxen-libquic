/*
    Test client binary
*/

#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

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

    std::vector<std::string> to_send;
    cli.add_option("file", to_send, "File(s) to stream to the server; each file will be sent in a parallel stream")
            ->type_name("FILE")
            ->expected(-1);

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
    auto msg = "hello from the other siiiii-iiiiide"_bsv;

    opt::client_tls client_tls{key, cert, server_cert};

    opt::local_addr client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = opt::local_addr{a, p};
    }

    auto [server_a, server_p] = parse_addr(remote_addr);
    opt::remote_addr server_addr{server_a, server_p};

    log::debug(log_cat, "Calling 'client_connect'...");
    auto client = client_net.client_connect(client_local, server_addr, client_tls);

    auto [ev_thread, running, done] = spawn_event_loop(client_net);

    running.get();  // Wait for ev thread to start
    log::debug(log_cat, "Main thread call");

    std::thread async_thread{[&] {
        log::debug(log_cat, "Async thread called");
        auto stream_a = client->open_stream();
        stream_a->send(msg);

        std::this_thread::sleep_for(1s);

        auto stream_b = client->open_stream();
        stream_b->send(msg);
    }};

    while (done.wait_for(3s) != std::future_status::ready)
        log::info(log_cat, "waiting...");

    async_thread.join();
    ev_thread.join();

    return 0;
}
