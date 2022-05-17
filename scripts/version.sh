#!/bin/bash

source ./packaging/makeenv

BUILD_VERSION="${VERSION}-${CDP_DEFINITION_BUILD_COUNT}"

echo "##vso[task.setvariable variable=CUSTOM_VERSION;]$BUILD_VERSION"
exit 0