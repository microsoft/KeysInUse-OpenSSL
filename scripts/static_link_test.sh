#!/bin/bash

set -e

# Install keysinuse package
if [ -e /etc/mariner-release ]; then
    rpm -i $(ls ./pkg/*.rpm)
else
    dpkg --force-depends -i $(ls ./pkg/*.deb)
fi

openssl version
openssl engine

# Rebuild the tests natively
/usr/bin/cmake -H./ -B./build
/usr/bin/cmake --build ./build --target keysinuse_test_common
/usr/bin/cmake --build ./build --target keysinuse_static_link

printf "\nStarting static link tests\n"
chmod 0755 ./bin/test/keysinuse_static_link
OPENSSL_CONF=$(/usr/bin/openssl version -d | awk '{gsub(/"/, "", $2); print $2}')/openssl.cnf ./bin/test/keysinuse_static_link