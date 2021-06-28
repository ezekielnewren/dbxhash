#pragma once

#include "DBXHash.h"

struct Context {
    Context(const Context&) = delete;
    void operator=(const Context&) = delete;

    DBXHash* hasher;
    int64_t block;
    int state = 0;

    byte data[4 * 1024 * 1024];
    byte hash[DIGEST_SIZE];
    std::streamsize size;


    Context(DBXHash* _hasher);
    void operator()();

};


