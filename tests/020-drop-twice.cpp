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

        // Repeats the race several times (fresh connection each time) because which of the
        // job queue's two processing batches ends up containing the second drop's deferred job -
        // the one with the pending reset_soon destructor, or an earlier one without it - depends
        // on real thread timing between this test and the endpoint's loop thread.
        for (int i = 0; i < 10; i++)
        {
            auto client_established = callback_waiter{[](Connection&) {}};

            Address client_local{};
            auto client_endpoint = net_client.endpoint(client_local, client_established);
            auto client_ci = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());

            auto& conn = *client_ci;
            auto& ep = *client_endpoint;

            // drop_connection's own teardown (delete_connection) removes the connection from the
            // endpoint's tracking immediately but defers the actual C++ destructor by one more
            // tick (job_queue.reset_soon), since some callers reach it from within a live
            // connection method. That gap is the bug's window: a second, independent caller (e.g.
            // a stateless reset arriving alongside an unrelated protocol error) can capture a
            // reference to the connection while it is still alive and have its own deferred job
            // run only after that reset_soon destructor has fired.
            TestHelper::drop_connection(ep, conn, io_error{CONN_STATELESS_RESET});

            // Waits for the first drop's own deferred job to run. At this point delete_connection
            // has already erased the connection from `conns` and queued its destructor via
            // reset_soon, but that destructor is itself only queued - not yet run - so `conn` is
            // still a live object.
            TestHelper::pump(ep);

            // Second drop: scheduled while `conn` is still live (matching every real caller, which
            // only ever reaches drop_connection through the connection's own currently-running
            // method), but its deferred job lands behind the pending reset_soon destructor and so
            // runs only after the connection has actually been destroyed.
            TestHelper::drop_connection(ep, conn, io_error{CONN_STATELESS_RESET});

            client_ci.reset();

            // Runs the reset_soon destructor, then the second drop's deferred job.
            TestHelper::pump(ep);
            TestHelper::pump(ep);
        }

        log::info(test_cat, "Survived {} iterations", 10);
    }

}  //  namespace oxen::quic::test
