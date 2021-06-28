#pragma once

#include <iostream>
#include <cstdint>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include <openssl/sha.h>

using std::cout;
using std::cerr;
using std::endl;
using std::string;

using boost::shared_ptr;
namespace fs = boost::filesystem;
typedef uint8_t byte;


static const int64_t BLOCK_SIZE = 4*1024*1024;
static const int64_t DIGEST_SIZE = 32;

struct Context;
struct DBXHash;

string hexify(byte* hash);


void hashblock(byte* hash, byte* block, uint32_t size);

enum st {
    st_free,
    st_partial,
    st_full,
    st_hashing,
    st_hashed,
};

struct Locker {
    shared_ptr<boost::mutex> lock;
    shared_ptr<boost::condition_variable> signal;
    boost::unique_lock<boost::mutex>* lockGuard;

    Locker(shared_ptr<boost::mutex> _lock, shared_ptr<boost::condition_variable> _signal) {
        assert(_lock != nullptr);
        assert(_signal != nullptr);
        this->lock = _lock;
        this->signal = _signal;
        this->lockGuard = new boost::unique_lock<boost::mutex>(*lock);
    }

    ~Locker() {
        this->signal->notify_all();
        delete this->lockGuard; lockGuard = nullptr;
    }

    void wait() const {
        this->signal->notify_all();
        this->signal->wait(*this->lockGuard);
    }
};


