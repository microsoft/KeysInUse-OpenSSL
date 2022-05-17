#!/bin/bash -e

set -e -v

if [ ! -e /etc/mariner-release ]; then
    apt-get install -y docker-ce docker-ce-cli containerd.io
fi

# Containers using Glibc

docker build --no-cache -t local/mariner-glibc:latest -f ./containers/Dockerfile-Mariner_Glibc .
docker build --no-cache -t local/mariner-test:latest -f ./containers/Dockerfile-Mariner_Test .
docker build --no-cache -t local/ubuntu-2004-test:latest -f ./containers/Dockerfile-Ubuntu_2004_Test .

docker run local/mariner-test:latest
docker run local/ubuntu-2004-test:latest

# Containers using Musl

docker build --no-cache -t local/alpine-musl:latest -f ./containers/Dockerfile-Alpine_Musl .
docker build --no-cache -t local/alpine-test:latest -f ./containers/Dockerfile-Alpine_Test .
docker build --no-cache -t local/ingress-customized:latest -f ./containers/Dockerfile-Ingress_Customized .

docker run local/alpine-test:latest
docker run local/ingress-customized:latest