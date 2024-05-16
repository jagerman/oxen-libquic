/*
    Tunnel client binary
*/

#include "tcp.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC tunneled test client"};
    std::string log_file = "stderr", log_level = "info";

    add_log_opts(cli, log_file, log_level);

    int num_conns{2};
    cli.add_option("-N,--num-conns", num_conns, "Number of remote server TCP backends for which to set up listeners (1/2/3)")
            ->check(CLI::Range(1, 3));
    uint16_t port_start = 0;
    cli.add_option(
            "-P,--port-start",
            port_start,
            "Port of the first tunnel (subsequent tunnels, with -N, will use incremental ports).  If omitted or 0 then all "
            "ports are randomized.");

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

    auto client_tls = GNUTLSCreds::make_from_ed_keys(TUNNEL_SEED, TUNNEL_PUBKEY);

    Address tunnel_client_local{LOCALHOST, 1111}, manual_client_local{LOCALHOST, 2222}, tunnel_server_local{LOCALHOST, 3333};

    Address localhost_blank{LOCALHOST, 0};

    // Remote manual server addresses
    std::vector<Address> remote_addrs{{LOCALHOST, 4444}, {LOCALHOST, 4455}, {LOCALHOST, 4466}};

    std::atomic<int> current_conn{0};

    std::vector<std::promise<void>> conn_proms{};
    std::vector<std::future<void>> conn_futures{};

    for (int i = 0; i < num_conns; ++i)
    {
        conn_proms.push_back(std::promise<void>{});
        conn_futures.push_back(conn_proms.back().get_future());
    }

    // Connectable addresses
    std::vector<RemoteAddress> connect_addrs{};

    for (auto& r : remote_addrs)
        connect_addrs.push_back(RemoteAddress{TUNNEL_PUBKEY, r});

    // Paths from manual client to remote manual server keyed to remote port
    std::unordered_map<uint16_t, Path> paths;

    for (auto& r : remote_addrs)
        paths.emplace(r.port(), Path{localhost_blank, r});

    /** key: remote address to which we are connecting
        value: tunneled quic connection
    */
    std::unordered_map<Address, tunneled_connection> _tunnels;

    std::atomic<uint16_t> next_port = port_start;
    auto manual_client_established = [&](connection_interface& ci) {
        auto path = ci.path();
        auto& remote = path.remote;

        tunneled_connection tunneled_conn{};
        auto port = port_start == 0 ? 0 : next_port++;
        tunneled_conn.listener = std::make_shared<TCPListener>(
                client_net.loop(),
                [&_tunnels, path](const make_tcp_stream& make_tcp) {
                    auto& remote = path.remote;

                    log::critical(test_cat, "");
                    auto it_a = _tunnels.find(remote);
                    if (it_a == _tunnels.end())
                        throw std::runtime_error{"Could not find tunnel to remote:{}!"_format(remote)};

                    log::critical(test_cat, "");
                    auto& conns = it_a->second.conns;
                    auto it_b = conns.find(remote.port());
                    if (it_b == conns.end())
                        throw std::runtime_error{"Could not find paired TCP-QUIC for remote port:{}"_format(remote.port())};

                    log::critical(test_cat, "");
                    auto& tcp_quic = it_b->second;
                    log::critical(test_cat, "");
                    auto& ci = tcp_quic.ci;

                    log::critical(test_cat, "");
                    assert(ci);

                    log::critical(test_cat, "");
                    log::info(test_cat, "Opening stream...");
                    log::critical(test_cat, "{}?", (bool)make_tcp);
                    log::critical(test_cat, "{}?", (bool)ci);
                    auto tcp_conn = make_tcp(*ci);
                    log::critical(test_cat, "");
                    Address src = tcp_conn->remote_addr();

                    log::critical(test_cat, "");
                    auto [it, _] = tcp_quic.tcp_conns[src].insert(std::move(tcp_conn));

                    log::critical(test_cat, "");
                    return *it;
                },
                port);

        log::info(
                test_cat,
                "Manual client established connection (path: {}); assigned TCPListener listening on {}",
                path,
                tunneled_conn.listener->local_addr());

        TCPQUIC tcp_quic{};
        tcp_quic.ci = ci.shared_from_this();

        if (auto [_, b] = tunneled_conn.conns.emplace(remote.port(), std::move(tcp_quic)); not b)
            throw std::runtime_error{"Failed to emplace tunneled_connection!"};

        _tunnels.emplace(remote, std::move(tunneled_conn));

        if (current_conn >= num_conns)
            throw std::runtime_error{
                    "Client cannot accept more than configured number ({}) of connections!"_format(num_conns)};

        conn_proms[current_conn].set_value();
        current_conn += 1;
    };

    try
    {
        std::shared_ptr<connection_interface> tunnel_ci;

        auto manual_client = client_net.endpoint(localhost_blank, opt::manual_routing{[&](const Path& p, bstring_view data) {
                                                     tunnel_ci->send_datagram(serialize_payload(data, p.remote.port()));
                                                 }});

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring buf) {
            auto p = deserialize_payload(buf);

            if (auto it = paths.find(p); it != paths.end())
                manual_client->manually_receive_packet(Packet{it->second, std::move(buf)});
            else
                throw std::runtime_error{"Could not find path for route to remote port:{}"_format(p)};
        };

        auto tunnel_client_established = callback_waiter{
                [&](connection_interface&) { log::info(test_cat, "Tunnel client established connection to remote!"); }};

        auto tunnel_client =
                client_net.endpoint(tunnel_client_local, recv_dgram_cb, opt::enable_datagrams{Splitting::ACTIVE});

        RemoteAddress tunnel_server_addr{TUNNEL_PUBKEY, tunnel_server_local};

        log::info(test_cat, "Connecting tunnel client to server...");

        tunnel_ci = tunnel_client->connect(tunnel_server_addr, client_tls, opt::keep_alive{10s}, tunnel_client_established);
        tunnel_client_established.wait();

        for (int i = 0; i < num_conns; ++i)
            manual_client->connect(connect_addrs[i], client_tls, manual_client_established, opt::keep_alive{10s});
        for (int i = 0; i < num_conns; ++i)
            conn_futures[i].wait();

        auto msg = "Client established {} tunneled connections:\n\n"_format(current_conn.load());

        for (auto& [addr, tun] : _tunnels)
        {
            auto backend_addr = addr;
            backend_addr.set_port(backend_addr.port() + 1111);
            msg += "\tTCP connections to {} will be tunneled to remote TCP connections to {}\n"_format(
                    tun.listener->local_addr(), backend_addr);
        }

        log::critical(test_cat, "{}", msg);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start client: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
