cmake_minimum_required(VERSION 3.21)
project(xxy)

set(CMAKE_CXX_STANDARD 14)

add_executable(xxy main.c)

target_link_libraries(xxy
        mbedtls
        mbedcrypto
        mbedx509
        )