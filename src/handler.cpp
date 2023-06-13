#include "handler.hpp"

extern "C"
{
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
}

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <thread>
#include <uvw.hpp>

#include "client.hpp"
#include "connection.hpp"
#include "context.hpp"
#include "crypto.hpp"
#include "endpoint.hpp"
#include "network.hpp"
#include "server.hpp"

namespace oxen::quic
{
    Handler::Handler(std::shared_ptr<uvw::Loop> loop_ptr, Network& net) : net{net}
    {
        ev_loop = loop_ptr;

        log::info(log_cat, "{}", (ev_loop) ? "Event loop successfully created" : "Error: event loop creation failed");
    }

    Handler::~Handler()
    {
        log::debug(log_cat, "Shutting down tunnel manager...");

        for (const auto& itr : clients)
            itr->client->~Client();

        for (const auto& itr : servers)
            itr.second->server->~Server();

        if (ev_loop)
        {
            ev_loop->walk(uvw::Overloaded{[](uvw::UDPHandle&& h) { h.close(); }, [](auto&&) {}});
            ev_loop->clear();
            ev_loop->stop();
            ev_loop->close();
            log::debug(log_cat, "Event loop shut down...");
        }

        clients.clear();
        servers.clear();
    }

    std::shared_ptr<uvw::Loop> Handler::loop()
    {
        return (ev_loop) ? ev_loop : nullptr;
    }

    void Handler::client_call_async(async_callback_t async_cb)
    {
        for (const auto& itr : clients)
        {
            itr->client->call_async_all(async_cb);
        }
    }

    void Handler::client_close()
    {
        for (const auto& c : clients)
        {}
    }

    void Handler::close_all()
    {
        if (!clients.empty())
        {
            for (const auto& ctx : clients)
                ctx->client->close_conns();
        }
    }

    Server* Handler::find_server(const Address& local)
    {
        if (auto it = servers.find(local); it != servers.end())
            return it->second->server.get();
        return nullptr;
    }
    Client* Handler::find_client(const Address& local)
    {
        for (auto& ctx : clients)
            if (ctx->local == local)
                return ctx->client.get();
        return nullptr;
    }

}  // namespace oxen::quic
