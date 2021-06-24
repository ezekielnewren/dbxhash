#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/thread.hpp>
#include <boost/chrono.hpp>

#include <openssl/sha.h>

using std::cout;
using std::cerr;
using std::endl;
using std::string;

using boost::shared_ptr;

namespace fs = boost::filesystem;

typedef uint8_t byte;

string hexify(byte* hash) {
    string x = boost::algorithm::hex(string((const char*) hash, 32));
    transform(x.begin(), x.end(), x.begin(), ::tolower);
    return x;
}

bool hashblock(byte* hash, byte* block, uint32_t size) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, block, size);
    SHA256_Final(hash, &sha256);
    return true;
}

struct Hasher;

struct Context {
    Hasher* hasher;
    uint32_t id;
    uint32_t job;
    shared_ptr<boost::thread> t;
    shared_ptr<boost::mutex> lock;
    boost::condition_variable more_work;
    int state = 0; // 0 IDLE, 1 FILLED, 2 HASHING, 3 HASHED

    byte block[4*1024*1024];
    byte hash[32];
    std::streamsize size;

    Context(Hasher* _hasher, int _id);

    void start() {
        t = shared_ptr<boost::thread>(new boost::thread(&Context::run, this));
    }

    void run();

};

struct Hasher {
    shared_ptr<boost::mutex> lock;
    boost::condition_variable cond_worker;
    boost::condition_variable cond_customer;

    Context** ctx;
    uint32_t threads;
    uint32_t job_submit;
    uint32_t job_complete;

    bool closed;
    byte hash[32];
    int* ring;

    SHA256_CTX sha256;

    Hasher(uint32_t _threads) {
        lock = shared_ptr<boost::mutex>(new boost::mutex);

        closed = false;
        this->threads = _threads;
        ctx = new Context*[threads];
        ring = new int[threads];
        for (int i=0; i<threads; i++) {
            ctx[i] = new Context(this, i);
        }
        SHA256_Init(&sha256);
    }

    ~Hasher() {
        delete[] ctx; ctx = nullptr;
        delete[] ring; ring = nullptr;
    }

    void run() {
        while (true) {
            boost::unique_lock<boost::mutex> m(*lock);
            if (closed) break;
            cond_worker.wait(m);
            if (closed) break;

            int j = job_submit++;


        }
    }

    void finish() {
        SHA256_Final(hash, &sha256);
    }

    static int BLOCK_SIZE;

    int inState(int state) {
        for (int i=0; i<threads; i++) {
            if (ctx[i]->state == state) return i;
        }
        return -1;
    }

    Context* next() {
        boost::unique_lock<boost::mutex> m(*lock);
        int id;
        while (true) {
            id = inState(0);
            if (id >= 0) break;
            cond_customer.wait(m);
        }
        return this->ctx[id];
    }

    void submit(Context* ctx) {
        boost::unique_lock<boost::mutex> m(*lock);
        assert(ctx->state == 0);
        ctx->state = 1;
        ctx->more_work.notify_one();
    }

    void close() {
        cond_customer.notify_one();
        cond_worker.notify_one();
        for (int i=0; i<threads; i++) {
            this->ctx[i]->more_work.notify_one();
        }
    }

};
int Hasher::BLOCK_SIZE = 4*1024*1024;

Context::Context(Hasher* _hasher, int _id) {
    this->hasher = _hasher;
    this->id = _id;
    this->lock = hasher->lock;
}

void Context::run() {
    while (true) {
        {
            boost::unique_lock<boost::mutex> m(*lock);
            if (hasher->closed) break;
            more_work.wait(m);
            if (hasher->closed) break;
            assert(state == 1);
            state = 2;
        }
        hashblock(hash, block, size);
        {
            boost::unique_lock<boost::mutex> m(*lock);
            if (hasher->closed) break;
            state = 3;
            if (hasher->job_complete == this->job) hasher->cond_worker.notify_one();
        }
    }
}




int main(int argc, char** argv) {
    if (argc <= 1) {
        cout << "not enough arguments" << endl;
        return 1;
    }

    uint32_t threads = boost::thread::hardware_concurrency();
    Hasher h(threads);

    fs::ifstream file((fs::path(argv[1])));
    if (! file.is_open()) {
        cerr << "failed to open file" << endl;
        return 2;
    }
    while (true) {
        Context* ctx = h.next();
        ctx->size = file.readsome((char*) ctx->block, Hasher::BLOCK_SIZE);
        if (ctx->size == 0) break;
        h.submit(ctx);
    }
    h.finish();
    cout << hexify(h.hash) << endl;

    file.close();

    return 0;
}
