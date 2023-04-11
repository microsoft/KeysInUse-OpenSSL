cmake_minimum_required(VERSION 3.10)

project(static_link_test)
find_package(OpenSSL REQUIRED)
find_package(Threads)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/engine/inc
    ./inc
    ../inc
)

set(OPENSSL_USE_STATIC_LIBS TRUE)

set(CMAKE_CXX_STANDARD 17)

add_executable(keysinuse_static_link main.cpp)

target_link_libraries(keysinuse_static_link
    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test/libkeysinuse_test_common.a
    ${CMAKE_SOURCE_DIR}/../openssl/libcrypto.a
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)