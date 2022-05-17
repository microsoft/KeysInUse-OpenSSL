cmake_minimum_required(VERSION 3.0.0)
project(keysinuse_engine)
find_package(OpenSSL REQUIRED)
find_library(CRYPTO_LIB libcrypto.so REQUIRED)

include_directories(
  ${OPENSSL_INCLUDE_DIR}
  ./inc
)

file (GLOB src_files
    ./src/*
)

add_library(keysinuse SHARED ${src_files})

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wno-unused-result \
  -Wformat -Wformat-security -Werror=format-security \
  -fstack-protector-strong \
  -O2 \
  -D_FORTIFY_SOURCE=2 \
  -z noexecstack")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -lcrypto -z relro -z now")
set(CMAKE_SHARED_LIBRARY_PREFIX "")

target_compile_definitions(keysinuse PUBLIC
  $<$<CONFIG:Debug>:DEBUG>
)

target_link_libraries(keysinuse
  ${CRYPTO_LIB}
)

include(CPack)
