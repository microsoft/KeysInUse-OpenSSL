cmake_minimum_required(VERSION 3.10)

project(memleak_detection)
find_package(OpenSSL REQUIRED)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
)

add_executable(memleak_detection
    main.c
)

if(USE_ASAN)
    if (${CMAKE_VERSION} VERSION_LESS "3.13")
        set_target_properties(keysinuse_unit PROPERTIES LINK_FLAGS "-fsanitize=address -fsanitize-recover=address")
    else()
        target_link_options(keysinuse_unit PRIVATE -fsanitize=address -fsanitize-recover=address)
    endif()
endif()

target_link_libraries(memleak_detection
    ${OPENSSL_CRYPTO_LIBRARY}
)