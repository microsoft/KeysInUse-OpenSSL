#!/bin/bash

set -e

mkdir -p /var/log/keysinuse
chmod 1733 /var/log/keysinuse

# Rebuild the tests natively
/usr/bin/cmake -H./ -B./build
/usr/bin/cmake --build ./build --target keysinuse_test_common
/usr/bin/cmake --build ./build --target keysinuse_unit

printf "\nStarting unit tests\n"
chmod 0755 ./bin/test/keysinuse_unit
./bin/test/keysinuse_unit