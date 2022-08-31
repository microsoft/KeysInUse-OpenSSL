cmake_minimum_required(VERSION 3.0.0)
project(keysinuse_engine)
find_package(OpenSSL REQUIRED)

include_directories(
  ${OPENSSL_INCLUDE_DIR}
  ./inc
)

file (GLOB src_files
    ./src/*
)

add_library(keysinuse SHARED ${src_files})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wno-unused-result \
  -Wformat -Wformat-security -Werror=format-security \
  -fstack-protector-strong \
  -O2 \
  -D_FORTIFY_SOURCE=2")

if(CMAKE_SYSTEM_PROCESSOR MATCHES amd64|x86_64)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -z noexecstack")
endif()

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -lcrypto -z relro -z now")
set(CMAKE_SHARED_LIBRARY_PREFIX "")

target_compile_definitions(keysinuse PUBLIC
  $<$<CONFIG:Debug>:DEBUG>
)

target_link_libraries(keysinuse
  ${OPENSSL_CRYPTO_LIBRARY}
)

include(CPack)
