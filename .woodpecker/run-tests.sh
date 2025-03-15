#!/bin/bash

cd build

cmd="./tests/alltests --success -T --no-ipv6 --colour-mode ansi"

if [ -n "$GDB" ]; then
    cmd="../utils/ci/drone-gdb.sh $cmd"
fi

if [ -n "$SKIP_0RTT" ]; then
    cmd="$cmd --disable-0rtt"
fi

set -e -x

$cmd
