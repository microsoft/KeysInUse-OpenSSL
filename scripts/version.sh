#!/bin/bash

source ./packaging/makeenv

if [ -z $BUILD_VERSION ]; then
    if [ "$CDP_BUILD_TYPE" == "Official" ]; then
        BUILD_VERSION=${VERSION}-${CDP_DEFINITION_BUILD_COUNT}
    elif [ "$CDP_BUILD_TYPE" == "PullRequest" ]; then
        BUILD_VERSION="pr.${VERSION}-${CDP_DEFINITION_BUILD_COUNT}"
    elif [ "$CDP_BUILD_TYPE" == "Buddy" ]; then
        BUILD_VERSION="buddy.${VERSION}-${CDP_DEFINITION_BUILD_COUNT}"
    else
        BUILD_VERSION="cdpx.${VERSION}-${CDP_DEFINITION_BUILD_COUNT}"
    fi
fi

echo "##vso[task.setvariable variable=CUSTOM_VERSION;]$BUILD_VERSION"
exit 0