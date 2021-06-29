#include "DBXHash.h"
#include "util.h"

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

using std::string;

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;


static int all = (int) boost::thread::hardware_concurrency();

template <typename Func>
void fill_buffer(Func& fun, byte* buffer, int64_t len) {
    for (int64_t i=0; i<len; i++) {
        buffer[i] = fun();
    }
}


BOOST_AUTO_TEST_CASE(dbxhash_milky_way) {
    boost::filesystem::ifstream file(boost::filesystem::path("milky-way-nasa.jpg"));

    byte hash[DIGEST_SIZE];

    DBXHash(all).process(file, hash, 8191);

    string guess = hexify(hash);

    string hash_milky_way = "485291fa0ee50c016982abbfa943957bcd231aae0492ccbaa22c58e3997b35e0";
    BOOST_CHECK(hash_milky_way == guess);
}


BOOST_AUTO_TEST_CASE(hashblock_milky_way) {
    boost::filesystem::ifstream file(boost::filesystem::path("milky-way-nasa.jpg"));

    byte hash[DIGEST_SIZE];
    byte block[BLOCK_SIZE];

    file.read((char*) block, BLOCK_SIZE);
    hashblock(hash, block, file.gcount());
    BOOST_CHECK("2a846fa617c3361fc117e1c5c1e1838c336b6a5cef982c1a2d9bdf68f2f1992a" == hexify(hash));

    file.read((char*) block, BLOCK_SIZE);
    hashblock(hash, block, file.gcount());
    BOOST_CHECK("c68469027410ea393eba6551b9fa1e26db775f00eae70a0c3c129a0011a39cf9" == hexify(hash));

    file.read((char*) block, BLOCK_SIZE);
    hashblock(hash, block, file.gcount());
    BOOST_CHECK("7376192de020925ce6c5ef5a8a0405e931b0a9a8c75517aacd9ca24a8a56818b" == hexify(hash));

    BOOST_CHECK(file.eof());

}

BOOST_AUTO_TEST_CASE(hash_random) {
    byte buffer[BLOCK_SIZE];
    byte hash_guess[DIGEST_SIZE];
    byte hash_correct[DIGEST_SIZE];

    boost::random::rand48 source;


    int loop = 100;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    source.seed(0);
    for (int j=0; j<loop; j++) {
        fill_buffer(source, buffer, BLOCK_SIZE);

        hashblock(hash_correct, buffer, BLOCK_SIZE);
        SHA256_Update(&sha256, hash_correct, DIGEST_SIZE);
    }
    SHA256_Final(hash_correct, &sha256);

    DBXHash h(all);
    source.seed(0);
    for (int j=0; j<loop; j++) {
        fill_buffer(source, buffer, BLOCK_SIZE);

        h.update(buffer, sizeof(buffer));
    }
    h.finish(hash_guess);

    string expected = hexify(hash_correct);
    string actual = hexify(hash_guess);
    BOOST_CHECK(expected == actual);

//    cout << hexify(hash) << endl;
}



