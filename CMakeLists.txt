cmake_minimum_required(VERSION 3.10.0)
project(dbxhash)

set(CMAKE_CXX_STANDARD 11)


set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)


set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.75.0 COMPONENTS system filesystem chrono iostreams regex thread program_options REQUIRED)

find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
add_executable(dbxhash main.cpp)
target_link_libraries(dbxhash ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL)

#target_link_libraries(dbxhash ssl crypto)
#target_link_libraries(dbxhash boost)
