#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("014 - 0rtt", "[014][0rtt]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();
        server_tls->enable_inbound_0rtt();
        client_tls->enable_outbound_0rtt();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        CHECK_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());
    }

}  //  namespace oxen::quic::test
