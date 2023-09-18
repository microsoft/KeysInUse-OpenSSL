cmake_minimum_required(VERSION 3.10)

project(functional_test)
find_package(OpenSSL REQUIRED)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/engine/inc
    ./inc
    ../inc
)

set(CMAKE_CXX_STANDARD 17)

file(GLOB src_files
    ./src/*.cpp
)

add_executable(keysinuse_functional ${src_files})

target_link_libraries(keysinuse_functional
    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test/libkeysinuse_test_common.a
    ${OPENSSL_CRYPTO_LIBRARY}
    -static-libstdc++
)