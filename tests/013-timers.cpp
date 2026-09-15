#include "unit_test.hpp"

namespace oxen::quic::test
{
    struct lifetime
    {};

    constexpr int NUM_ITERATIONS{4};
    constexpr auto INTERVAL{10ms};
    constexpr auto DELAY{2 * NUM_ITERATIONS * INTERVAL};

// Ticker and Wakeable are deprecated in favour of JobQueue::add_timer(), but are still tested until
// they are removed.  Delete this block, and the two cases below it, along with the classes.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    TEST_CASE("013 - Ticker event repeater (deprecated)", "[013][ticker][deprecated]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<void> prom_a, prom_b;
        std::future<void> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        std::shared_ptr<Ticker> handler;

        stream_data_callback server_data_cb = [&recv_counter](Stream&, std::span<const std::byte>) { recv_counter++; };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        handler = test_net.loop()->call_every(INTERVAL, [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                send_counter += 1;
                client_stream->send(msg, nullptr);
            }
        });

        handler->start();

        test_net.loop()->call_later(DELAY, [&prom_a] { prom_a.set_value(); });

        require_future(fut_a, 5s);
        REQUIRE(recv_counter == send_counter);

        recv_counter = 0;
        send_counter = 0;

        REQUIRE(handler->start());

        test_net.loop()->call_later(DELAY, [&prom_b] { prom_b.set_value(); });

        require_future(fut_b, 5s);
        REQUIRE(recv_counter == send_counter);
    }

    TEST_CASE("013 - Wakeable event handler (deprecated)", "[013][wakeable][deprecated]")
    {
        Loop loop;

        std::promise<void> prom;
        std::atomic<int> i = 0;

        auto w = loop.make_wakeable([&i, &prom] {
            ++i;
            prom.set_value();
        });

        w->wake();
        auto fut = prom.get_future();

        require_future(fut, 1s);
        REQUIRE(i == 1);

        std::promise<void> prom2, prom5;
        w = loop.make_wakeable([&i, &prom2, &prom5] {
            auto v = ++i;
            if (v == 2)
                prom2.set_value();
            else if (v == 5)
                prom5.set_value();
        });

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });

        auto fut2 = prom2.get_future();
        require_future(fut2, 1s);
        REQUIRE(i == 2);

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });
        std::this_thread::sleep_for(25ms);
        w->wake();
        std::this_thread::sleep_for(25ms);
        w->wake();
        auto fut5 = prom5.get_future();
        require_future(fut5, 1s);
        REQUIRE(i == 5);
    }

#pragma GCC diagnostic pop

    TEST_CASE("013 - Timer: repeating", "[013][timer][repeat]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        auto id = loop.add_timer(10ms, [&] {
            if (++i == 4)
                prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, 1s);

        REQUIRE(loop.stop(id));
        auto stopped_at = i.load();
        std::this_thread::sleep_for(50ms);
        REQUIRE(i == stopped_at);

        // A stopped job is paused, not removed: it can be restarted.
        loop.repeat(id, 10ms);
        std::this_thread::sleep_for(50ms);
        REQUIRE(i > stopped_at);

        REQUIRE(loop.remove(id));
        REQUIRE_FALSE(loop.remove(id));
    }

    TEST_CASE("013 - Timer: manual trigger is idempotent", "[013][timer][wake]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        auto id = loop.add_wakeable([&] { ++i; });

        // No interval, so nothing should fire on its own.
        std::this_thread::sleep_for(25ms);
        REQUIRE(i == 0);

        loop.call_get([&] {
            for (int n = 0; n < 100; n++)
                loop.wake(id);
        });
        std::this_thread::sleep_for(25ms);
        REQUIRE(i == 1);

        loop.wake(id);
        std::this_thread::sleep_for(25ms);
        REQUIRE(i == 2);

        loop.remove(id);
    }

    TEST_CASE("013 - Timer: stopped timer is still wakeable", "[013][timer][wake][repeat]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        auto id = loop.add_timer(10ms, [&] {
            if (++i == 3)
                prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, 1s);

        REQUIRE(loop.armed(id));

        // Descheduling leaves the timer registered, so it can still be fired by hand -- and doing
        // so must not start it repeating again.
        REQUIRE(loop.stop(id));
        REQUIRE_FALSE(loop.armed(id));
        auto stopped_at = i.load();
        std::this_thread::sleep_for(50ms);
        REQUIRE(i == stopped_at);

        loop.wake(id);
        std::this_thread::sleep_for(25ms);
        REQUIRE(i == stopped_at + 1);

        loop.wake(id);
        std::this_thread::sleep_for(25ms);
        REQUIRE(i == stopped_at + 2);

        // Still not repeating on its own: waking does not arm it.
        REQUIRE_FALSE(loop.armed(id));
        std::this_thread::sleep_for(50ms);
        REQUIRE(i == stopped_at + 2);

        loop.remove(id);
    }

    TEST_CASE("013 - Timer: waking a repeating timer resets its cycle", "[013][timer][wake][repeat]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        auto id = loop.add_timer(80ms, [&] { ++i; });

        // Fire it manually well before the first tick is due; the tick should then be rescheduled a
        // full interval from now rather than firing at its original time.
        std::this_thread::sleep_for(20ms);
        loop.wake(id);
        std::this_thread::sleep_for(20ms);
        REQUIRE(i == 1);

        // Original tick would have been due around here had the wake not re-phased it.
        std::this_thread::sleep_for(40ms);
        REQUIRE(i == 1);

        loop.remove(id);
    }

    TEST_CASE("013 - Timer: removal from inside its own callback", "[013][timer][remove]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;
        TimerID id;

        loop.call_get([&] {
            id = loop.add_timer(5ms, [&] {
                if (++i == 3)
                {
                    loop.remove(id);
                    prom.set_value();
                }
            });
        });

        auto fut = prom.get_future();
        require_future(fut, 1s);

        std::this_thread::sleep_for(50ms);
        REQUIRE(i == 3);
        REQUIRE_FALSE(loop.remove(id));
    }

    TEST_CASE("013 - Timer: unknown ids", "[013][timer][errors]")
    {
        Loop loop;

        auto id = loop.add_timer([] {});
        REQUIRE(loop.remove(id));

        // Teardown operations and queries on a dead id are silent; scheduling ones throw.
        REQUIRE_FALSE(loop.armed(id));
        REQUIRE_FALSE(loop.stop(id));
        REQUIRE_FALSE(loop.remove(id));
        REQUIRE_THROWS(loop.wake(id));
        REQUIRE_THROWS(loop.repeat(id, 10ms));
    }

    TEST_CASE("013 - Timer: call_later still fires once", "[013][timer][call_later]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        loop.call_later(10ms, [&] {
            ++i;
            prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, 1s);

        std::this_thread::sleep_for(50ms);
        REQUIRE(i == 1);
    }

}  //  namespace oxen::quic::test
