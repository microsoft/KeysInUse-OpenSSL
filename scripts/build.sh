#!/bin/bash -e

set -e -v

cmake -DCMAKE_TOOLCHAIN_FILE=./cmake-toolchains/linux-amd64-glibc.cmake -H./ -B./build
cmake --build ./build --target all