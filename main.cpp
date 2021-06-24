#include <iostream>
#include <cstdint>
#include <fstream>

#include <boost/filesystem.hpp>

using std::cout;
using std::endl;

namespace fs = boost::filesystem;

typedef uint8_t byte;

#include <openssl/sha.h>
bool hashblock(byte* hash, byte* block, uint32_t size) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, block, size);
    SHA256_Final(hash, &sha256);

    return true;
}

int main(int argc, char** argv) {
    if (argc < 1) {
        cout << "not enough arguments" << endl;
    }

    byte buff[4*1024*1024];
    byte hash[32];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);



    std::ifstream file(argv[1]);
    while (true) {
        file.read((char*) buff, sizeof(buff));
        std::streamsize read = file.gcount();
        if (read <= 0) break;
        hashblock(hash, buff, read);
        SHA256_Update(&sha256, hash, sizeof(hash));
    }
    SHA256_Final(hash, &sha256);

    file.close();


    std::cout << "Hello, World!" << std::endl;
    return 0;
}
