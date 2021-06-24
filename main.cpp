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

struct Context {
    byte block[4*1024*1024];
    std::streamsize size;
};

struct Hasher {
    boost::mutex lock;
    Context* ctx;
    boost::condition_variable cond;
    bool _finish = false;

    SHA256_CTX sha256;

    Hasher(int threads) {
        ctx = new Context[threads];
        SHA256_Init(&sha256);
    }

    ~Hasher() {
        delete[] ctx; ctx = nullptr;
    }

    void run() {
        while (true) {
            boost::unique_lock<boost::mutex> l(lock);
            cond.wait(l);

            if (_finish) break;
        }
    }

    void finish(byte* hash) {
        SHA256_Final(hash, &sha256);
    }




};


int main(int argc, char** argv) {
    if (argc <= 1) {
        cout << "not enough arguments" << endl;
        return 1;
    }

    byte buff[4*1024*1024];
    byte hash[32];



    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    boost::system::error_code ec;
    fs::path p = fs::current_path();
    cout << p << endl;

    fs::ifstream file((fs::path(argv[1])));
    if (! file.is_open()) {
        cerr << "failed to open file" << endl;
    }
    while (true) {
        int amount = sizeof(buff);
        std::streamsize read = file.readsome((char*) buff, amount);
//        file.read((char*) buff, amount);
//        std::streamsize read = file.gcount();
        if (read <= 0) break;
        hashblock(hash, buff, read);
        cout << hexify(hash) << endl;
        SHA256_Update(&sha256, hash, sizeof(hash));
    }
    SHA256_Final(hash, &sha256);
    cout << hexify(hash) << endl;


    file.close();


    std::cout << "Hello, World!" << std::endl;
    return 0;
}
