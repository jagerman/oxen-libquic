/*
    Test server binary
*/

#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string key{"./serverkey.pem"}, cert{"./servercert.pem"};

    cli.add_option("-c,--certificate", cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-k,--key", key, "Path to server key to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    // TODO: make this optional
    std::string client_cert{"./clientcert.pem"};
    cli.add_option("-C,--clientcert", key, "Path to client certificate for client authentication")
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

    Network server_net{};

    opt::server_tls server_tls{key, cert, client_cert};

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    opt::local_addr server_local{listen_addr, listen_port};

    auto stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id);
        return 0;
    };
    auto stream_data = [&](Stream& s, bstring_view data) {
        log::warning(test_cat, "Got some stream data from stream {}: {}B", s.stream_id, data.size());
    };

    log::debug(test_cat, "Calling 'server_listen'...");
    auto server = server_net.server_listen(server_local, server_tls, stream_opened, stream_data);

    log::debug(test_cat, "Starting event loop thread...");
    auto [ev_thread, running, done] = spawn_event_loop(server_net);

    while (done.wait_for(3s) != std::future_status::ready)
        log::info(test_cat, "waiting...");

    ev_thread.join();

    return 0;
}
