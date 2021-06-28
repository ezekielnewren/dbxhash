
#include <string>
#include <iostream>

#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "DBXHash.h"

using std::cout;
using std::cerr;
using std::string;


string hash_milky_way = "485291fa0ee50c016982abbfa943957bcd231aae0492ccbaa22c58e3997b35e0";
//string hash_milky_way = "485291fa0ee50c016982abbfa943957bcd231aae0492ccbaa22c58e3997b35e1";

//BOOST_AUTO_TEST_CASE(test1) {
void test_milky_way() {
    boost::filesystem::ifstream file(boost::filesystem::path("milky-way-nasa.jpg"));

    byte hash[DIGEST_SIZE];
    DBXHash(12).process(file, hash);

    string guess = hexify(hash);

    BOOST_CHECK(hash_milky_way == guess);
}


test_suite*
init_unit_test_suite( int argc, char* argv[] ) {
    test_suite* test = BOOST_TEST_SUITE( "Master test suite" );

    test->add( BOOST_TEST_CASE( &test_milky_way ) );

    return test;
}





