//
// Created by zeke on 6/28/21.
//

#include "Context.h"

Context::Context(DBXHash* _hasher) {
    this->hasher = _hasher;
}

void Context::operator()() {
    {
        Locker m(hasher->lock, hasher->signal);
        assert(state == st_full);
        state = st_hashing;
    }
    hashblock(hash, data, size);
    // cout << block+1 << " " << hexify(hash) << " 0x" << std::hex << (uint64_t) hash << endl;
    {
        Locker m(hasher->lock, hasher->signal);
        assert(state == st_hashing);
        state = st_hashed;
        hasher->window[block%hasher->threads] = this;

        for (int i=0; i<hasher->threads; i++) {
            int64_t a = hasher->block_complete;
            Context* c = hasher->window[a%hasher->threads];
            if (c == nullptr) break;
            int64_t b = c->block;
            assert(a == b);
            SHA256_Update(&hasher->sha256, c->hash, DIGEST_SIZE);
            hasher->block_complete++;
            c->size = 0;
            c->state = st_free;
            hasher->window[a%hasher->threads] = nullptr;
        }
    }
}