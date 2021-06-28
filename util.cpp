#include "util.h"



string hexify(byte* hash) {
    string x = boost::algorithm::hex(string((const char*) hash, DIGEST_SIZE));
    transform(x.begin(), x.end(), x.begin(), ::tolower);
    return x;
}

void hashblock(byte* hash, byte* block, uint32_t size) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, block, size);
    SHA256_Final(hash, &sha256);
}


