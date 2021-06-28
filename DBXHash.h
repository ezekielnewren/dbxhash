//
// Created by zeke on 6/28/21.
//

#pragma once
#include <cstdint>

#include "util.h"
#include "Context.h"

struct DBXHash {
    DBXHash(const DBXHash&) = delete;
    DBXHash& operator=(const DBXHash&) = delete;

    shared_ptr<boost::mutex> lock;
    shared_ptr<boost::condition_variable> signal;

    uint32_t threads;
    int64_t block_complete;
    int64_t block_submit;

    shared_ptr<boost::asio::thread_pool> pool;

    Context** memory;
    Context** window;
    Context* partial;

    SHA256_CTX sha256;

    explicit DBXHash(uint32_t threads);
    virtual ~DBXHash();

    void finish(byte *hash);

    Context *findContext(int state);

    void submit(Context *c);

    void update(byte *buffer, int64_t len);

    void process(std::istream &in, byte *hash, int64_t bufferSize=BLOCK_SIZE);
};





