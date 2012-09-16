#include "interface.hpp"
#include "digests.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";
	unsigned char buf[16];

	MD5_CTX ctx;
	BOOST_CHECK(MD5_Init(&ctx));

	BOOST_CHECK(MD5_Update(&ctx, str, strlen(str) + 1));

	BOOST_CHECK(MD5_Final(buf, &ctx));
}

BOOST_AUTO_TEST_CASE(CHECK_TEST)
{
	const char *str = "ofsoul";

	unsigned char left[16];
	MD5_CTX ctx_left;
	MD5_Init(&ctx_left);
	MD5_Update(&ctx_left, str, strlen(str));
	MD5_Final(left, &ctx_left);

	crypto<encode::md5::_128bit> code;
	byte_array right = code.execute((unsigned char*)str, strlen(str));

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(0, memcmp(left, &right[0], encode::md5::_128bit::BLOCK_COUNT));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";

	crypto<encode::md5::_128bit> code;
	byte_array val = code.execute((const unsigned char*)str, strlen(str));

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(encode::md5::_128bit::BLOCK_COUNT, val.size());
}

BOOST_AUTO_TEST_SUITE_END()