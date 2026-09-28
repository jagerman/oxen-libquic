#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("020 - drop_connection's deferred job outliving the connection", "[020][drop_twice]")
    {
        Network net_client;
        Network net_server;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        auto server_endpoint = net_server.endpoint(server_local, [](Connection&) {});
        server_endpoint->listen(server_tls);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        // Whether the second drop's job runs before or after the connection is destroyed depends on
        // timing between this thread and the loop thread, so repeat to hit both orderings.  If it
        // runs before, the unfixed code fires the close callback twice; if after, it is a
        // use-after-free (which only ASan will reliably catch).
        for (int i = 0; i < 10; i++)
        {
            std::atomic<int> closes{0};
            auto client_established = callback_waiter{[](Connection&) {}};
            auto client_closed = [&closes](Connection&, uint64_t) { closes++; };

            Address client_local{};
            auto client_endpoint = net_client.endpoint(client_local, client_established, client_closed);
            auto client_ci = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

            auto& conn = *client_ci;
            auto& ep = *client_endpoint;

            // The first drop's job removes the connection from the endpoint and hands the
            // endpoint's reference to a reset_soon job.  `client_ci` still keeps it alive, so the
            // second drop below is scheduled on a live connection, as every real caller does.
            TestHelper::drop_connection(ep, conn, io_error{CONN_STATELESS_RESET});
            TestHelper::pump(ep);

            TestHelper::drop_connection(ep, conn, io_error{CONN_STATELESS_RESET});

            // Whichever of this and the reset_soon job drops the last reference destroys the
            // connection, and that can land on either side of the second drop's job.
            client_ci.reset();

            TestHelper::pump(ep);
            TestHelper::pump(ep);

            CHECK(closes == 1);
        }
    }

}  //  namespace oxen::quic::test
