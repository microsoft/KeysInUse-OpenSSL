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
if(USE_ASAN)
    if (${CMAKE_VERSION} VERSION_LESS "3.13")
        set_target_properties(keysinuse_unit PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-recover=address")
    else()
        target_link_options(keysinuse_unit PRIVATE -fsanitize=address -fsanitize-recover=address)
    endif()
endif()

target_link_libraries(keysinuse_unit
    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test/libkeysinuse_test_common.a
    ${OPENSSL_CRYPTO_LIBRARY}
    -lstdc++fs
)