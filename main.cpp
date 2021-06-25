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
    st_partial,
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
    int64_t block_complete;
    int64_t block_submit;

    shared_ptr<boost::asio::thread_pool> pool;

    Context** memory;
    Context** window;
    Context* partial;

    SHA256_CTX sha256;

    Hasher(uint32_t _threads) {
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

    ~Hasher() {
        for (int i=0; i<threads; i++) {
            delete memory[i];
            memory[i] = nullptr;
        }
        delete[] memory; memory = nullptr;
        delete[] window; window = nullptr;
    }

    void finish(byte* hash) {
        Locker m(lock, signal);
        if (partial != nullptr) submit(partial);
        while (block_complete < block_submit) m.wait();
        SHA256_Final(hash, &sha256);
    }

    Context* findContext(int state) {
        for (int i=0; i<threads; i++) {
            if (memory[i]->state == state) return memory[i];
        }
        return nullptr;
    }

    void submit(Context* c) {
        assert(c->state == st_partial);
        c->state = st_full;
        c->block = block_submit++;
        partial = nullptr;
        boost::asio::post(*pool, boost::bind(&Context::operator(), c));
    }

    void update(byte* buffer, int64_t len) {
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

    void process(std::istream& in, byte* hash) {
        int64_t bufferSize = BLOCK_SIZE;
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

namespace po = boost::program_options;
void po_keyless(po::basic_parsed_options<char>& opts, std::vector<string>& keyless) {
    for (int j=0; j<opts.options.size(); j++) {
        po::basic_option<char> a = opts.options.at(j);
        if (a.string_key == "") {
            for (int i=0; i<a.value.size(); i++) {
                keyless.push_back(a.value[i]);
            }
        }
    }
}

int main(int argc, char** argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("threads", po::value<string>(), "'all', 'half', or specify the number of threads to use");

    po::variables_map vm;
    po::basic_parsed_options<char> x = po::parse_command_line(argc, argv, desc);
    po::store(x, vm);
    po::notify(vm);

    std::vector<string> keyless;
    po_keyless(x, keyless);

    if (vm.count("help")) {
        cout << desc << endl;
        return 0;
    }

    // file list
    bool read_from_stdin = false;
    for (auto& v : keyless) {
        if (v == "-") {
            read_from_stdin = true;
            break;
        }
    }
    if (read_from_stdin and keyless.size() > 1) {
        cerr << "reading from stdin must be the only file argument if it is present" << endl;
        return 1;
    }
    if (keyless.empty()) read_from_stdin = true;

    // number of threads to use
    int all = (int) boost::thread::hardware_concurrency();
    int threads = all;
    if (vm.count("threads")) {
        string arg_threads = vm["threads"].as<string>();
        if (arg_threads == "all") threads = all;
        else if (arg_threads == "half") threads = all/2;
        else {
            int amount = boost::lexical_cast<int>(arg_threads);
            threads = std::min(std::max(amount, 1), all);
        }
    }


    byte hash[DIGEST_SIZE];

    if (read_from_stdin) {
        Hasher(threads).process(std::cin, hash);
        cout << hexify(hash) << "  -" << endl;
    } else {
        for (string& path: keyless) {
            fs::ifstream file((fs::path(path)));
            if (! file.is_open()) {
                cerr << "failed to open file" << endl;
                return 2;
            }
            Hasher(threads).process(file, hash);
            cout << hexify(hash) << "  " << path << endl;
            file.close();
        }
    }

    return 0;
}
