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

if [ -e /etc/mariner-release ]; then
    make LABEL=${LABEL} rpm
else
    make LABEL=${LABEL} deb
fi
