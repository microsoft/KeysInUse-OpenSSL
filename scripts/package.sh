#!/bin/bash -e

set -e -v

if [ -z $LABEL ]; then
    BUILDNUM=${CDP_DEFINITION_BUILD_COUNT:-0}
    if [ "$CDP_BUILD_TYPE" == "Official" ]; then
        LABEL=${BUILDNUM}
    elif [ "$CDP_BUILD_TYPE" == "PullRequest" ]; then
        LABEL="pr.${BUILDNUM}"
    elif [ "$CDP_BUILD_TYPE" == "Buddy" ]; then
        LABEL="buddy.${BUILDNUM}"
    else
        LABEL="cdpx.${BUILDNUM}"
    fi
fi

go version
cd packaging

#amd64 or aarch64
CONFIG=$1

if ([ -e /etc/mariner-release ] && [ "$2" != "deb" ]) || [ "$2" = "rpm" ]; then
    make LABEL=${LABEL} CONFIG=${CONFIG} rpm
else
    make LABEL=${LABEL} CONFIG=${CONFIG} deb
fi
