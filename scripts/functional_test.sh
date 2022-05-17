#!/bin/bash

set -e

# Don't fail tests for memory leaks in OpenSSL code
export LSAN_OPTIONS=exitcode=0

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
/usr/bin/cmake --build ./build --target keysinuse_functional

# https://github.com/openssl/openssl/issues/17962 causes this to fail
# on ubuntu 20.04 test machines. Reinstalling OpenSSL <1.1.1n does not work.
# When OpenSSL 1.1.1o releases, update the pipeline.

printf "\nStarting functional tests\n"
chmod 0755 ./bin/test/keysinuse_functional
./bin/test/keysinuse_functional