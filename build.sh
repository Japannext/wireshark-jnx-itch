#!/usr/bin/env sh

set -ex

autoreconf -v -i
./configure
make
# make install-home
