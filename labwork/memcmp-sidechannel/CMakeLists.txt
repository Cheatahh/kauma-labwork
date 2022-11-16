cmake_minimum_required(VERSION 3.22)
project(memcmp_sidechannel C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-O2)
add_executable(memcmp_sidechannel main.c)
