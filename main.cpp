#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/thread.hpp>
#include <boost/chrono.hpp>
#include <boost/asio.hpp>

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
    int id;
    int block;
    int state = 0; // 0 IDLE, 1 FILLED, 2 HASHING, 3 HASHED

    byte data[4 * 1024 * 1024];
    byte hash[32];
    std::streamsize size;

    Context(Hasher* _hasher, int _id);
    void operator()();

};

struct Hasher {
    shared_ptr<boost::mutex> lock;
    boost::condition_variable cond_worker;
    boost::condition_variable cond_customer;

    Context** ctx;
    uint32_t threads;
    int64_t block_submit;
    int64_t block_complete;

    shared_ptr<boost::asio::thread_pool> pool;


    bool closed;
    bool eof;
    byte hash[32];
    int64_t* ring;

    SHA256_CTX sha256;

    Hasher(uint32_t _threads) {
        lock = shared_ptr<boost::mutex>(new boost::mutex);

        closed = false;
        eof = false;
        block_complete = block_submit = 0;


        this->threads = _threads;
        pool = shared_ptr<boost::asio::thread_pool>(new boost::asio::thread_pool(threads));
        ctx = new Context*[threads];
        ring = new int64_t[threads];
        for (int i=0; i<threads; i++) {
            ctx[i] = new Context(this, i);
            ring[i] = (int64_t) -1;
        }
        SHA256_Init(&sha256);
        boost::asio::post(*pool, boost::bind(&Hasher::run, this));
    }

    ~Hasher() {
        delete[] ctx; ctx = nullptr;
        delete[] ring; ring = nullptr;
    }

    void run() {
        while (true) {
            int count = 0;
            {
                boost::unique_lock<boost::mutex> m(*lock);
                if (closed or (eof and block_complete == block_submit))
                    break;
                cond_worker.wait(m);
                if (closed or (eof and block_complete == block_submit))
                    break;

                for (int i=0; i<threads; i++) {
                    if (ring[(block_complete + i) % threads] < 0) break;
                    count++;
                }
                assert(count > 0);
            }

            for (int i=0; i<count; i++) {
                Context* c = ctx[ring[(block_complete + i) % threads]];
                SHA256_Update(&sha256, c->hash, sizeof(c->hash));
            }

            {
                boost::unique_lock<boost::mutex> m(*lock);
                for (int i=0; i<count; i++) {
                    Context* c = ctx[ring[(block_complete + i) % threads]];
                    c->state = 0;
                    ring[(block_complete + i) % threads] = -1;
                }

                block_complete += count;
                cond_customer.notify_one();
            }


        }
    }

    void finish() {
        boost::unique_lock<boost::mutex> m(*lock);
        eof = true;
        while (block_complete < block_submit) {
            cond_customer.wait(m);
        }
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
        int64_t block = (block_submit++) % threads;
        ctx->block = block;
        ring[block] = -1;
        boost::asio::post(*pool, *ctx);
    }

    void close() {
        cond_customer.notify_one();
        cond_worker.notify_one();
    }

};
int Hasher::BLOCK_SIZE = 4*1024*1024;

Context::Context(Hasher* _hasher, int _id) {
    this->hasher = _hasher;
    this->id = _id;
}

void Context::operator()() {
    {
        boost::unique_lock<boost::mutex> m(*hasher->lock);
        if (hasher->closed) return;
        assert(state == 1);
        state = 2;
    }
    hashblock(hash, data, size);
    cout << block+1 << " " << hexify(hash) << endl;
    {
        boost::unique_lock<boost::mutex> m(*hasher->lock);
        if (hasher->closed) return;
        state = 3;
        hasher->ring[block] = id;
        hasher->cond_customer.notify_one();
        if (hasher->block_complete == this->block) hasher->cond_worker.notify_one();
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
        ctx->size = file.readsome((char*) ctx->data, Hasher::BLOCK_SIZE);
        if (ctx->size == 0) break;
        h.submit(ctx);
    }
    h.finish();
    cout << hexify(h.hash) << endl;

    file.close();

    return 0;
}
