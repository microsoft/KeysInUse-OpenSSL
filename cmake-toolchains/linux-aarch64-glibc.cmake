# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Point clang sysroot to cross compilation toolchain when cross compiling
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES ARM64|aarch64)
    message(STATUS "Using cross compilation toolchain")

    set(TARGET_TRIPLE aarch64-linux-gnu)

    # C/C++ toolchain (installed on Ubuntu using apt-get gcc-aarch64-linux-gnu g++-aarch64-linux-gnu)
    set(CMAKE_SYSROOT_COMPILE /usr/${TARGET_TRIPLE})

    # Currently only use clang as it makes cross-compilation easier
    set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})
    set(CMAKE_C_COMPILER clang)
    set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
    set(CMAKE_CXX_COMPILER clang++)
    set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

    # We would expect setting SYSROOT to be sufficient for clang to cross-compile with the gcc-aarch64-linux-gnu
    # toolchain, but it seems that this misses a few key header files for C++...
    # Hacky solution which seems to work for Ubuntu + clang:
    # Get CMake to find the appropriate include directory and explicitly include it
    # Seems like there should be a better way to install cross-compilation tools, or specify search paths to clang
    find_path(CXX_CROSS_INCLUDE_DIR NAMES ${TARGET_TRIPLE} PATHS /usr/${TARGET_TRIPLE}/include/c++/ PATH_SUFFIXES 15 14 13 12 11 10 9 8 7 6 5 NO_DEFAULT_PATH)
    add_compile_options(-I${CXX_CROSS_INCLUDE_DIR}/${TARGET_TRIPLE})
endif()

set(USE_ASAN OFF CACHE BOOL "Use address sanitizers for compiling test applications")
add_compile_options(-O3)