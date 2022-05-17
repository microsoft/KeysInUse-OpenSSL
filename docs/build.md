# Build

Multiple binaries are built from this repo, including the keysinuse engine, unit and functional tests for the engine, install and packaging utilities, and Debian and RPM packages for the engine. This document outlines how to build each component.

# Dependencies
## Engine
- CMake version &#8805; 3.0.0
- OpenSSL version 1.1.1
- C compiler (preferably gcc)
## Tests
- C++ compiler with support for C++14 or higher (preferably g++)
## Packages
- Make
- Go &#8805; 1.16
- dpkg-deb
- rpmbuild

The engine has been developed using gcc, and the tests have been developed using g++. They have been tested with the glibc and musl implementations of the C standard library.

# Engine and Tests (CMake)
The engine shared object and tests are built using CMake. The CMakeLists are organized to allow building all targets from the project root.
1. Initialize the project (Only need to run once)  
`/usr/bin/cmake -DCMAKE_TOOLCHAIN_FILE=<path_to_toolchain> -DCMAKE_BUILD_TYPE:STRING=Debug -H./ -B./build`
    - Change `Debug` to `Release` to disable debug logging from the engine
    - CMake toolchain files are located in [cmake-toolchains](../cmake-toolchains/). Use the correct toolchain file for your target system.
2. Build  
`/usr/bin/cmake --build ./build --config Debug --target <target name>`

## Cmake targets
| target | description |
| --- | --- |
| all | Engine binary and all tests |
| keysinuse | Engine shared object
| keysinuse_test_common | Static library of functions shared between tests
| keysinuse_functional | Engine functional tests. Includes headers from the engine but makes test calls through OpenSSL APIs
| keysinuse_unit | Engine unit tests. Directly links to engine code for test
| keysinuse_latency | Engine latency tests. Makes calls through OpenSSL APIs to benchmark crypto performance

# Packages
The package root (`/packaging`) contains a top level Makefile that can be used to build both Debian and RPM packages, as well as the package utilities. The Debian and RPM packages are placed in the package root.

| Make Target | Description |
| --- | --- |
| all | Builds debian and RPM packages and utilities|
| deb | Builds debian package |
| rpm | Builds RPM package |
| ../bin/keysinuseutil | Builds keysinuse install/uninstall utility
| ../bin/pkgupload | Builds keysinuse package upload helper
| clean | Removes previously generated build files

# Compiled Binaries
All binaries are binplaced in the `/bin` folder.
| Binary name | Description |
| --- | --- |
| `/bin/keysinuse.so` | Keys-in-use engine for OpenSSL
| `/bin/keysinuseutil` | Lightweight install utility for packaging. When the keysinuse package is installed/uninstalled, this tool performs the OpenSSL config changes needed to enable the engine by default, and prepare the node |
| `/bin/pkgupload` | Utility for uploading the keysinuse packages to packages.microsoft.com. |
| `./bin/test/keysinuse_functional` | Functional tests that ensure keysinuse engine functiosn on a node configured to use the engine shared object. Verifies correct logging behavior for calls made to `RSA`, `EVP_PKEY`, and `RSA_EVP` APIs |
| `./bin/test/keysinuse_unit` | Unit tests that link to the engine source and ensure the logging and throttling functions behave correctly |
| `./bin/test/keysinuse_latency` | Benchmark test to assess the impact of the keysinuse engine on crypto performance |