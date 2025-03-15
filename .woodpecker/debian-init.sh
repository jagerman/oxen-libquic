#!/bin/bash

echo "Building on $(hostname)"

# This script should be passed debian package names to install, or some +group which will be
# replaced with the package groups defined below.  For instance, `debian-init.sh +default jq` will
# install all the deps in the "default" entry and the `jq` package.  If no arguments are given at
# all then that is equivalent to specifying +default (use +none if you really want nothing).
declare -A deps
deps[basic]="cmake git pkg-config ccache"
deps[old_base]="${deps[basic]} libevent-dev libsodium-dev gnutls-bin"
deps[old]="${deps[old_base]} g++"
deps[base]="${deps[old_base]} libcli11-dev libfmt-dev libspdlog-dev libgnutls28-dev"
deps[default]="${deps[base]} g++"
deps[with_ngtcp2]="${deps[default]} libngtcp2-dev libngtcp2-crypto-gnutls-dev"
deps[none]=""  # +none installs no packages at all (no argument would install the default set)

pkgs=()
for d in "$@"; do
    if [[ "$d" == +* ]]; then
        d="${d:1}"
        if [ -n "${deps[$d]}" ]; then
            pkgs+=(${deps[$d]})
        else
            echo "$0: Unknown debian dep group +$d" >&2
            exit 1
        fi
    else
        pkgs+=("$d")
    fi
done

if [ "$#" -eq 0 ]; then
    pkgs+=(${deps[default]})
fi

set -e -x

echo "man-db man-db/auto-update boolean false" | debconf-set-selections
apt-get -o=Dpkg::Use-Pty=0 -q update
apt-get -o=Dpkg::Use-Pty=0 -q install -y eatmydata
if [ "${#pkgs[@]}" -gt 0 ]; then
    eatmydata apt-get -o=Dpkg::Use-Pty=0 -q install -y --no-install-recommends "${pkgs[@]}"
fi
