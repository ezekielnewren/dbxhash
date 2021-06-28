//
// Created by zeke on 6/28/21.
//

#include "DBXHash.h"
#include "Context.h"

DBXHash::DBXHash(uint32_t _threads) {
    lock = shared_ptr<boost::mutex>(new boost::mutex);
    signal = shared_ptr<boost::condition_variable>(new boost::condition_variable());

    this->threads = _threads;
    this->block_complete = 0;
    this->block_submit = 0;

    pool = shared_ptr<boost::asio::thread_pool>(new boost::asio::thread_pool(threads));
    memory = new Context*[threads];
    window = new Context*[threads];
    partial = nullptr;
    for (int i=0; i<threads; i++) {
    memory[i] = new Context(this);
    window[i] = nullptr;
    }
    SHA256_Init(&sha256);
}

DBXHash::~DBXHash() {
    for (int i=0; i<threads; i++) {
        delete memory[i];
        memory[i] = nullptr;
    }
    delete[] memory; memory = nullptr;
    delete[] window; window = nullptr;
}

void DBXHash::finish(byte* hash) {
    Locker m(lock, signal);
    if (partial != nullptr) submit(partial);
    while (block_complete < block_submit) m.wait();
    SHA256_Final(hash, &sha256);
}

Context* DBXHash::findContext(int state) {
    for (int i=0; i<threads; i++) {
        if (memory[i]->state == state) return memory[i];
    }
    return nullptr;
}

void DBXHash::submit(Context* c) {
    assert(c->state == st_partial);
    c->state = st_full;
    c->block = block_submit++;
    partial = nullptr;
    boost::asio::post(*pool, boost::bind(&Context::operator(), c));
}

void DBXHash::update(byte* buffer, int64_t len) {
    int64_t off = 0;
    if (len == 0) return;
    Locker m(lock, signal);
    while (true) {
        Context* c;
        if (partial != nullptr) c = partial;
        else {
            while (true) {
                c = findContext(st_free);
                if (c != nullptr) break;
                m.wait();
            }
            assert(c->state == st_free);
            c->state = st_partial;
        }
        int64_t amount = std::min(BLOCK_SIZE-c->size, std::min(BLOCK_SIZE, len));
        memcpy(c->data+c->size, buffer+off, amount);
        c->size += amount; off += amount; len -= amount;

        if (c->size == BLOCK_SIZE) submit(c);
        else partial = c;
        assert(len >= 0);
        if (len == 0) break;
    }
}

void DBXHash::process(std::istream& in, byte* hash, int64_t bufferSize) {
    shared_ptr<byte> buffer((byte*) malloc(bufferSize), free);
    while (true) {
        in.clear();
        if (!in.read((char*) buffer.get(), bufferSize) and !in.eof()) {
            cerr << std::hex << in.fail() << " error reading the file" << endl;
        }
        int64_t read = in.gcount();
        if (read == 0) break;
        update(buffer.get(), read);
    }
    finish(hash);
}
