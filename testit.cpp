#include "DBXHash.h"
#include "util.h"

using std::string;

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;





BOOST_AUTO_TEST_CASE(dbxhash_milky_way) {
    boost::filesystem::ifstream file(boost::filesystem::path("milky-way-nasa.jpg"));

    byte hash[DIGEST_SIZE];

    int all = (int) boost::thread::hardware_concurrency();
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





