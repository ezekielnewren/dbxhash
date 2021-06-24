#include <iostream>
#include <cstdint>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
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

enum st {
    st_free,
    st_alloc,
    st_full,
    st_hashing,
    st_hashed,
};



struct Context {
    Hasher* hasher;
    int64_t block;
    int state = 0;

    byte data[4 * 1024 * 1024];
    byte hash[32];
    std::streamsize size;

    Context(Hasher* _hasher);
    void operator()();

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

    void wait() {
        this->signal->notify_all();
        this->signal->wait(*this->lockGuard);
    }


};

struct Hasher {
    shared_ptr<boost::mutex> lock;
    shared_ptr<boost::condition_variable> signal;

    Context** ctx;
    uint32_t threads;
    int64_t block_submit;
    int64_t block_complete;

    shared_ptr<boost::asio::thread_pool> pool;


    bool closed;
    bool eof;
    byte hash[32];
    Context** ring;

    SHA256_CTX sha256;

    Hasher(uint32_t _threads) {
        lock = shared_ptr<boost::mutex>(new boost::mutex);
        signal = shared_ptr<boost::condition_variable>(new boost::condition_variable());

        closed = false;
        eof = false;
        block_complete = block_submit = 0;


        this->threads = _threads;
        pool = shared_ptr<boost::asio::thread_pool>(new boost::asio::thread_pool(threads));
        ctx = new Context*[threads];
        ring = new Context*[threads];
        for (int i=0; i<threads; i++) {
            ctx[i] = new Context(this);
            ring[i] = nullptr;
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
            Locker m(lock, signal);
            int count = 0;

            if (closed or (eof and block_complete == block_submit)) break;
            while (true) {
                for (int i=0; i<threads; i++) {
                    Context* c = ring[(block_complete+i)%threads];
                    if (!(c != nullptr and c->state == st_hashed)) break;
                    count++;
                }
                if (count > 0) break;
                if (closed or (eof and block_complete == block_submit)) break;
                m.wait();
                if (closed or (eof and block_complete == block_submit)) break;
            }
            if (closed or (eof and block_complete == block_submit)) break;
            assert(count > 0);

            for (int i=0; i<count; i++) {
                // get context
                Context* c = ring[(block_complete+i)%threads];
                assert(block_complete == c->block);
                cout << c->block << " " << hexify(c->hash) << endl;

                // consume hashes
                SHA256_Update(&sha256, c->hash, sizeof(c->hash));
                c->state = st_free;
                ring[(c->block)%threads] = nullptr;
            }

            block_complete += count;
        }
    }

    void finish() {
        Locker m(lock, signal);
        eof = true;
        while (!(block_complete == block_submit)) m.wait();
        SHA256_Final(hash, &sha256);
    }

    static int BLOCK_SIZE;

    Context* findFree(int state) {
        for (int i=0; i<threads; i++) {
            if (ctx[i]->state == state) return ctx[i];
        }
        return nullptr;
    }

    Context* next() {
        Locker m(lock, signal);
        Context* c;
        while (true) {
            c = findFree(st_free);
            if (c != nullptr) break;
            m.wait();
        }
        assert(c->state == st_free);
        c->state = st_alloc;
        return c;
    }

    void submit(Context* c) {
        Locker m(lock, signal);
        assert(c->state == st_alloc);
        c->state = st_full;
        c->block = block_submit++;
        ring[c->block%threads] = c;
        boost::asio::post(*pool, *c);
    }

    void close() {
        Locker m(lock, signal);
        closed = true;
    }

};
int Hasher::BLOCK_SIZE = 4*1024*1024;

Context::Context(Hasher* _hasher) {
    this->hasher = _hasher;
}

void Context::operator()() {
    {
        Locker m(hasher->lock, hasher->signal);
        assert(state == st_full);
        state = st_hashing;
    }
    hashblock(hash, data, size);
//    cout << block+1 << " " << hexify(hash) << endl;
    {
        Locker m(hasher->lock, hasher->signal);
        assert(state == st_hashing);
        state = st_hashed;
        hasher->ring[block%hasher->threads] = this;
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
        Context* c = h.next();
        assert(c->state == st_alloc);
        c->size = file.readsome((char*) c->data, Hasher::BLOCK_SIZE);
        if (c->size == 0) break;
        h.submit(c);
    }
    h.finish();
    cout << hexify(h.hash) << endl;

    file.close();

    return 0;
}
