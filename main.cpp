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

//#include <boost/shared_array.hpp>
//using boost::shared_array;
using boost::shared_ptr;
namespace fs = boost::filesystem;
typedef uint8_t byte;


static const int BLOCK_SIZE = 4*1024*1024;
static const int DIGEST_SIZE = 32;

string hexify(byte* hash) {
    string x = boost::algorithm::hex(string((const char*) hash, DIGEST_SIZE));
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

    Context(const Context&) = delete;
    void operator=(const Context&) = delete;

    Hasher* hasher;
    int64_t block;
    int state = 0;

    byte data[4 * 1024 * 1024];
    byte hash[DIGEST_SIZE];
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

    void wait() const {
        this->signal->notify_all();
        this->signal->wait(*this->lockGuard);
    }


};

struct Hasher {

    Hasher(const Hasher&) = delete;
    void operator=(const Hasher&) = delete;

    shared_ptr<boost::mutex> lock;
    shared_ptr<boost::condition_variable> signal;

    uint32_t threads;
    int64_t block_submit;
    int64_t block_complete;

    shared_ptr<boost::asio::thread_pool> pool;


    bool closed;
    bool eof;
    byte hashOverall[DIGEST_SIZE];
    Context** memory;
    Context** window;

    SHA256_CTX sha256;

    Hasher(uint32_t _threads) {
        lock = shared_ptr<boost::mutex>(new boost::mutex);
        signal = shared_ptr<boost::condition_variable>(new boost::condition_variable());

        closed = false;
        eof = false;
        block_complete = block_submit = 0;


        this->threads = _threads;
        pool = shared_ptr<boost::asio::thread_pool>(new boost::asio::thread_pool(threads));
        memory = new Context*[threads];
        window = new Context*[threads];
        for (int i=0; i<threads; i++) {
            memory[i] = new Context(this);
            window[i] = nullptr;
        }
        SHA256_Init(&sha256);
    }

    ~Hasher() {
        for (int i=0; i<threads; i++) {
            delete memory[i];
            memory[i] = nullptr;
        }
        delete[] memory; memory = nullptr;
        delete[] window; window = nullptr;
    }

    void finish() {
        Locker m(lock, signal);
        eof = true;
        while (!(block_complete == block_submit)) m.wait();
        SHA256_Final(hashOverall, &sha256);
    }

    Context* findContext(int state) {
        for (int i=0; i<threads; i++) {
            if (memory[i]->state == state) return memory[i];
        }
        return nullptr;
    }

    void submit(byte* buffer, int64_t len) {
        // int64_t off = 0;
        Locker m(lock, signal);
        Context* c;
        while (true) {
            c = findContext(st_free);
            if (c != nullptr) break;
            m.wait();
        }
        assert(c->state == st_free);
        memcpy(c->data, buffer, len);
        c->size = len;

        c->state = st_full;
        c->block = block_submit++;
        window[c->block%threads] = c;

        boost::asio::post(*pool, boost::bind(&Context::operator(), c));
//        boost::asio::post(*pool, *c);
    }

    void hashmore() {
        for (int i=0; i<threads; i++) {
            int64_t a = block_complete+i;
            Context* c = window[a%threads];
            int64_t b = c->block;
            assert(a == b);
            if (!(block_complete == c->block and c->state == st_hashed)) break;
            cout << c->block+1 << " " << hexify(c->hash) << " 0x" << std::hex << (uint64_t) c->hash << endl;
            // cout << c->block+1 << " " << hexify(c->hash) << endl;
            SHA256_Update(&sha256, c->hash, DIGEST_SIZE);
            block_complete++;
            c->state = st_free;
        }
    }

    void close() {
        Locker m(lock, signal);
        closed = true;
    }

};


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
//    cout << block+1 << " " << hexify(hash) << " 0x" << std::hex << (uint64_t) hash << endl;
    {
        Locker m(hasher->lock, hasher->signal);
        assert(state == st_hashing);
        state = st_hashed;

        hasher->hashmore();
    }
}




int main(int argc, char** argv) {
    if (argc <= 1) {
        cout << "not enough arguments" << endl;
        return 1;
    }

    uint32_t threads = boost::thread::hardware_concurrency();
    threads = 1;
    Hasher h(threads);
    byte hash[DIGEST_SIZE];

    fs::ifstream file((fs::path(argv[1])));
    if (! file.is_open()) {
        cerr << "failed to open file" << endl;
        return 2;
    }
    byte buffer[BLOCK_SIZE];
    while (true) {
        int64_t read = file.readsome((char*) buffer, BLOCK_SIZE);
        if (read == 0) break;
        hashblock(hash, buffer, read);
        // cout << "main " << hexify(hash) << endl;
        h.submit(buffer, read);
    }
    h.finish();
    cout << hexify(h.hashOverall) << endl;

    file.close();

    return 0;
}
