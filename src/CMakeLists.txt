
option(LIBQUIC_LIBUV_PACKET_QUEUE "Enables the libuv UDP packet queuing code; disables sendmmsg/GSO support" OFF)
option(LIBQUIC_SENDMMSG "Enables sendmmsg() use when sending UDP packets, if supported on this system" ON)
option(LIBQUIC_SEND_GSO "Enables GSO support, if supported on this system (requires LIBQUIC_SENDMMSG=ON)" ON)
option(LIBQUIC_RECVMMSG "Enables recvmmsg() use when receiving UDP packets, if supported on this system" ON)


add_library(quic
    client.cpp
    connection.cpp
    context.cpp
    crypto.cpp
    endpoint.cpp
    handler.cpp
    network.cpp
    opt.cpp
    server.cpp
    stream.cpp
    utils.cpp
)

target_link_libraries(quic
    PUBLIC
    ngtcp2::crypto
    gnutls
    uvw::uvw-static
    oxen::logging
    common
    PRIVATE
    internal
)

if(LIBQUIC_LIBUV_PACKET_QUEUE)
    message(STATUS "Building with libuv UDP packet queuing")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_LIBUV_QUEUING)
elseif(NOT LIBQUIC_SENDMMSG)
    message(STATUS "Building without sendmmsg support")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_NO_SENDMMSG)
elseif(NOT LIBQUIC_SEND_GSO)
    message(STATUS "Building without GSO support")
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_UDP_NO_GSO)
else()
    message(STATUS "Building with sendmmsg/GSO, if available on this platform")
endif()

if(NOT LIBQUIC_RECVMMSG)
    target_compile_definitions(quic PUBLIC OXEN_LIBQUIC_LIBUV_NO_RECVMMSG)
    message(STATUS "Building without recvmmsg support")
else()
    message(STATUS "Building with recvmmsg, if available on this platform")
endif()
