#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("010 - Migration", "[010][migration]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{}, client_secondary{}, client_local_b{};

        std::promise<void> d_promise;
        std::promise<void> conn_promise_a, conn_promise_b, conn_promise_c;

        auto d_future = d_promise.get_future();
        auto conn_future_a = conn_promise_a.get_future();
        auto conn_future_b = conn_promise_b.get_future();
        auto conn_future_c = conn_promise_c.get_future();

        std::atomic<bool> address_flipped = false, secondary_connected = false;

        std::shared_ptr<Endpoint> client_endpoint;
        std::shared_ptr<Connection> server_ci;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(view(dat) == good_msg);
            d_promise.set_value();
        };

        auto server_established = callback_waiter{[](Connection&) {}};
        auto client_established_b = callback_waiter{[](Connection&) { log::trace(test_cat, "LOOK ME UP BRO"); }};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        server_endpoint->listen(server_tls, server_data_cb);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = [&](Connection& ci) mutable {
            if (not address_flipped)
            {
                auto& conn = static_cast<Connection&>(ci);

                SECTION("NAT Rebinding")
                {
                    TestHelper::nat_rebinding(conn, client_secondary);
                }

                SECTION("Migration")
                {
                    TestHelper::migrate_connection(conn, client_secondary);
                }

                // Uncomment this when NGTCP2 releases v1.2.0
                SECTION("Immediate migration")
                {
                    TestHelper::migrate_connection_immediate(conn, client_secondary);
                }

                address_flipped = true;
                conn_promise_a.set_value();
            }
            else
            {
                if (not secondary_connected)
                {
                    log::trace(test_cat, "Skipping address flip!");
                    secondary_connected = true;
                    conn_promise_b.set_value();
                }
                else
                {
                    conn_promise_c.set_value();
                }
            }
        };

        client_endpoint = test_net.endpoint(client_local, client_established);
        auto original_addr = client_endpoint->local();
        client_endpoint->listen(client_tls);

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(server_established.wait());
        require_future(conn_future_a);

        auto client_stream = client_ci->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));
        require_future(d_future);

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        std::this_thread::sleep_for(5ms);
        RemoteAddress client_remote_b{defaults::CLIENT_PUBKEY, LOCALHOST, client_ci->local().port()};

        REQUIRE_FALSE(original_addr == client_ci->local());

        auto client_endpoint_b = test_net.endpoint(client_local_b, client_established_b);
        auto client_ci_b = client_endpoint_b->connect(client_remote_b, client_tls);

        require_future(conn_future_b);
        CHECK(client_established_b.wait());
    }

    TEST_CASE("010 - A change of the host's source address migrates the connection", "[010][migration][network]")
    {
        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::mutex received_mutex;
        std::string received;
        std::condition_variable received_cv;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mutex};
            received += view(dat);
            received_cv.notify_all();
        };
        auto wait_for_received = [&](std::string_view expected) {
            std::unique_lock lock{received_mutex};
            return received_cv.wait_for(lock, 5s, [&] { return received == expected; });
        };

        auto server_endpoint = test_net.endpoint(Address{"127.0.0.1", 0});
        server_endpoint->listen(server_tls, server_data_cb);
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1", server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{ipv4{}}, client_established);
        if (!TestHelper::simulate_local_address(*client_endpoint, std::nullopt))
            SKIP("Simulating a change of the host's address requires a debug build of libquic");
        const auto port = client_endpoint->local().port();

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());
        CHECK(conn->local() == Address{"127.0.0.1", port});

        auto stream = conn->open_stream();
        stream->send("one"s);
        REQUIRE(wait_for_received("one"));

        // The host moves to a different network: the server's acknowledgement of "two" arrives on
        // the new address, and the client migrates to it.
        const Address new_local{"127.0.0.2", port};
        REQUIRE(TestHelper::simulate_local_address(*client_endpoint, new_local));
        stream->send("two"s);
        REQUIRE(wait_for_received("onetwo"));

        for (int i = 0; i < 100 && conn->local() != new_local; i++)
            std::this_thread::sleep_for(10ms);
        CHECK(conn->local() == new_local);
        auto ngtcp2_local = TestHelper::ngtcp2_path_local(*conn);
        INFO("ngtcp2 path local: " << ngtcp2_local.to_string());
        CHECK(ngtcp2_local == new_local);

        stream->send("three"s);
        CHECK(wait_for_received("onetwothree"));
    }
}  // namespace oxen::quic::test
