#!/bin/bash -e

set -e

if [ -e /etc/mariner-release ]; then
    tdnf install -y ca-certificates-microsoft build-essential openssl-devel cmake rpm-build
    rpm -q openssl-devel
else
    # OneBranch Ubuntu 20.04 build image does not come with CMake
    apt-get update
    apt-get install -y cmake

    # Print the version of libssl being used for build
    apt-cache policy libssl-dev
fi

if [ $1 = "aarch64" ]; then
    echo "Building for aarch64"
    cmake -DCMAKE_TOOLCHAIN_FILE=./cmake-toolchains/linux-arm64-glibc.cmake -DOPENSSL_ROOT_DIR=$2 -H./ -B./build
else
    cmake -DCMAKE_TOOLCHAIN_FILE=./cmake-toolchains/linux-amd64-glibc.cmake -H./ -B./build
fi