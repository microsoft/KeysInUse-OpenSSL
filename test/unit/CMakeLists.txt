cmake_minimum_required(VERSION 3.10)

project(unit_test)
find_package(OpenSSL REQUIRED)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/engine/inc
    ../inc
)

set(CMAKE_CXX_STANDARD 17)

add_executable(keysinuse_unit
    main.cpp
    ${CMAKE_SOURCE_DIR}/engine/src/common.c
    ${CMAKE_SOURCE_DIR}/engine/src/logging.c
)

target_compile_definitions(keysinuse_unit PUBLIC
  DEBUG
)

target_link_libraries(keysinuse_unit
    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test/libkeysinuse_test_common.a
    ${OPENSSL_CRYPTO_LIBRARY}
    -lstdc++fs
)