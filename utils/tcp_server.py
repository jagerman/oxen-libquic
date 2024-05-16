#!/usr/bin/env python3

import argparse
import socket
import sys
import time

READSIZE = 4096

parser = argparse.ArgumentParser("Simple TCP Server")
parser.add_argument(
    "--localip",
    default="127.0.0.1",
    help="The local IP address on which to bind the TCP client socket",
    type=str,
)
parser.add_argument(
    "--localport",
    required=True,
    help="The local port on which to bind the TCP client socket",
    type=int,
)
parser.add_argument(
    "--pause-every",
    default=0,
    help="Pause reading (for 5s) each time after reading [this many] bytes",
    type=int,
)

if __name__ == "__main__":
    argvars = vars(parser.parse_args())

    LOCALIP = argvars["localip"]
    LOCALPORT = argvars["localport"]

    print("Starting TCP server...")

    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind((LOCALIP, LOCALPORT))
    serversock.listen(1)

    print("TCP server listening at {}:{}...".format(LOCALIP, LOCALPORT))

    while True:
        try:
            conn, addr = serversock.accept()
            remote = "{}:{}".format(addr[0], addr[1])

            print("\nAccepted connection from {}".format(remote))

            pause_at = argvars["pause_every"]
            if pause_at <= 0:
                pause_at = float('inf')

            size = 0
            while True:
                b = conn.recv(READSIZE)
                size += len(b)
                if not b:
                    break
                if size > pause_at:
                    print(f"Read {size}B; pausing for 5s... ", end="", flush=True)
                    time.sleep(5)
                    pause_at += argvars["pause_every"]
                    print("resuming")

            print("Received {}B from {}".format(size, remote))

            conn.sendall(bytes("{}".format(size), encoding="utf8"))

            # conn.shutdown(socket.SHUT_RDWR)
            conn.close()

            print("Connection to {} closed!".format(remote))

        except socket.error or ConnectionError or ConnectionResetError or RuntimeError:
            print("Remote {} disconnected! Continuing...".format(remote))
            conn.close()
            pass

        except KeyboardInterrupt:
            print("Shutting down TCP server...")
            serversock.shutdown(socket.SHUT_RDWR)
            serversock.close()
            sys.exit()
