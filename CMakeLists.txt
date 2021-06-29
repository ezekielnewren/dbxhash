cmake_minimum_required(VERSION 3.10.0)
project(dbxhash)
enable_testing()

set(CMAKE_CXX_STANDARD 11)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.65.0 COMPONENTS system filesystem chrono iostreams regex thread program_options REQUIRED)

# set(OPENSSL_USE_STATIC_LIBS TRUE)  ## doesn't work
find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

add_executable(dbxhash main.cpp DBXHash.cpp DBXHash.h Context.cpp Context.h util.h util.cpp)
target_link_libraries(dbxhash ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL)

## stuff for testing
find_package(Boost 1.65.0 COMPONENTS system filesystem chrono iostreams regex thread program_options unit_test_framework random REQUIRED)
add_executable(dbxhashtest testit.cpp DBXHash.cpp DBXHash.h Context.cpp Context.h util.h util.cpp)
target_link_libraries(dbxhashtest ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL)

set(UNIT_TEST dbxhashtest)
add_test(NAME ${UNIT_TEST} COMMAND ${UNIT_TEST} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
#add_custom_command(
#    TARGET ${UNIT_TEST}
#    COMMENT "Run tests"
#    POST_BUILD
#    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
#    COMMAND ${CMAKE_CTEST_COMMAND} -R "^${UNIT_TEST}$" --output-on-failures
#)


