#!/bin/bash

if ! [ -e readme.md ] || ! [ -e LICENSE ] || ! [ -e CMakeLists.txt ]; then
    echo "$0: must run this script from the project root!" >&2
    exit 1
fi

orig_args=("$@")
defaulted_arg() {
    name="$1"
    default="$2"
    for d in "${orig_args[@]}"; do
        if [[ $d == "$name"=* ]]; then
            return
        fi
    done
    echo "$name=$default"
}

set -e -x

mkdir build
cd build
cmake .. -DCMAKE_COLOR_DIAGNOSTICS=ON \
    $(defaulted_arg -DCMAKE_BUILD_TYPE Release) \
    $(defaulted_arg -DWARNINGS_AS_ERRORS OFF) \
    $(defaulted_arg -DWITH_LTO ON) \
    $(defaulted_arg -DLIBQUIC_BUILD_TESTS ON) \
    $(defaulted_arg -DLOCAL_MIRROR https://oxen.rocks/deps) \
    "$@"

make -j${JOBS:-6} VERBOSE=1
