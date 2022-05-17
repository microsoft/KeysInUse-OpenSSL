project(keysinuse_openssl)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test)

add_subdirectory (common)
add_subdirectory (functional)
add_subdirectory (unit)
add_subdirectory (latency)