#include "utils.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("009 - ALPNs", "[009][alpns][execute]")
    {
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};
        opt::handshake_timeout timeout{500ms};

        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto client_established2 = callback_waiter{[](connection_interface&) {}};

        // this has to destroy *after* network, in case it doesn't go off before then
        auto client_closed = callback_waiter{[](connection_interface&, uint64_t) {}};

        Network test_net{};

        SECTION("Default ALPN")
        {
            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "default"_usp);
        }

        SECTION("No Server ALPNs specified (defaulted)")
        {
            opt::alpns client_alpns{opt::alpns::DIR::O, "client"_usp};

            auto server_endpoint = test_net.endpoint(server_local, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("No Client ALPNs specified (defaulted)")
        {
            opt::alpns server_alpns{opt::alpns::DIR::I, "client"_usp, "relay"_usp};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Client ALPNs not supported")
        {
            opt::alpns server_alpns{opt::alpns::DIR::I, "client"_usp, "relay"_usp};
            opt::alpns client_alpns{opt::alpns::DIR::O, "foobar"_usp};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Select first ALPN both sides support")
        {
            opt::alpns server_alpns{opt::alpns::DIR::I, "client"_usp, "relay"_usp};
            opt::alpns client_alpns{opt::alpns::DIR::O, "client"_usp};
            opt::alpns client_alpns2{opt::alpns::DIR::O, "relay"_usp};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local, client_established, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "client"_usp);

            auto client_endpoint2 = test_net.endpoint(client_local, client_established2, client_alpns2, timeout);

            auto conn2 = client_endpoint2->connect(client_remote, client_tls);
            REQUIRE(client_established2.wait());
            REQUIRE(conn2->selected_alpn() == "relay"_usp);
        }

        SECTION("Bidirectional ALPN incoming")
        {
            opt::alpns server_alpns{opt::alpns::DIR::IO, "special-alpn"_usp};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            opt::alpns client_alpns{opt::alpns::DIR::O, "foobar"_usp};
            auto client_endpoint = test_net.endpoint(client_local, client_established, client_closed, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            CHECK(client_closed.wait(2s));
            REQUIRE_FALSE(client_established.is_ready());
        }

        SECTION("Bidirectional ALPN outgoing")
        {
            opt::alpns server_alpns{opt::alpns::DIR::I, "special-alpn"_usp};

            auto server_endpoint = test_net.endpoint(server_local, server_alpns, timeout);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            opt::alpns client_alpns{opt::alpns::DIR::IO, "special-alpn"_usp};
            auto client_endpoint = test_net.endpoint(client_local, client_established, client_alpns, timeout);

            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());
            REQUIRE(conn->selected_alpn() == "special-alpn"_usp);
        }
    }

}  // namespace oxen::quic::test
