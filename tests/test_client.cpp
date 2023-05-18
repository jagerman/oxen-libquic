/*
    Test client binary
*/

#include "quic.hpp"

#include <thread>


using namespace oxen::quic;


bool run{true};

void
signal_handler(int)
{
    run = false;
}


int main(int argc, char* argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    logger_config();

    Network client_net{};
    auto msg = "hello from the other siiiii-iiiiide"_bsv;

    opt::client_tls client_tls{
        0, 
        "/home/dan/oxen/libquicinet/tests/clientkey.pem"s, 
        "/home/dan/oxen/libquicinet/tests/clientcert.pem"s, 
        "/home/dan/oxen/libquicinet/tests/servercert.pem"s,
        ""s,
        nullptr};

    opt::local_addr client_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
    opt::remote_addr client_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    log::debug(log_cat, "Calling 'client_connect'...");
    auto client = client_net.client_connect(client_local, client_remote, client_tls);
    
    log::debug(log_cat, "Starting event loop...");
    client_net.ev_loop->run();

    return 0;
}

/*
    TODO:
        - start event loop in a separate thread
            std::thread ev_thread{[&] { run_event_loop(); }};
        - make other calls in another thread
        - join threads
            ev_thread.join
*/
