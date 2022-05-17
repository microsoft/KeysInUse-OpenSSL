cmake_minimum_required(VERSION 2.8)

project(latency_test)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

add_executable (keysinuse_latency
    main.cpp
)

target_link_libraries(keysinuse_latency
    LINK_PUBLIC
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY}
)