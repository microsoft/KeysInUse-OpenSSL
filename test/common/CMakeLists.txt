cmake_minimum_required(VERSION 2.8)

project(test_common)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test)

find_package(OpenSSL REQUIRED)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/engine/inc
    ../inc
)

set(CMAKE_CXX_STANDARD 17)

file(GLOB src_files
    ./*.cpp
)

add_library(keysinuse_test_common STATIC ${src_files})

target_link_libraries(keysinuse_test_common LINK_PUBLIC ${OPENSSL_CRYPTO_LIBRARY})