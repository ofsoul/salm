#include "interface.hpp"
#include "transforms.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(LIBRARY)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";

	crypto<encode::base64> en;
	std::string enbuf = en.execute((const unsigned char*)str, strlen(str));

	crypto<decode::base64> de;
	byte_array ret = de.execute(enbuf);

	BOOST_CHECK_EQUAL(std::string(str), salm::bytes_to_string(ret));
}

BOOST_AUTO_TEST_SUITE_END()