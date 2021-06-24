cmake_minimum_required(VERSION 3.19)
project(dbxhash)

set(CMAKE_CXX_STANDARD 11)


add_executable(dbxhash main.cpp)
target_link_libraries(dbxhash ssl crypto)

