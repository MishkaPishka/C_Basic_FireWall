cmake_minimum_required(VERSION 3.15)
project(untitled C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gdwarf-2")
set(CMAKE_C_STANDARD 99)
add_executable(untitled    nfqnl_test.c)
