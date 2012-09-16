#include "interface.hpp"
#include "digests.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";
	unsigned char buf[20];

	SHA_CTX ctx;
	BOOST_CHECK(SHA1_Init(&ctx));

	BOOST_CHECK(SHA1_Update(&ctx, str, strlen(str) + 1));

	BOOST_CHECK(SHA1_Final(buf, &ctx));
}

//sha와 sha1은 다른 결과값을 리턴한다. salm은 sha1을 지원한다.
BOOST_AUTO_TEST_CASE(SHA_COMPARISON_TEST)
{
	const char *str = "ofsoul";

	unsigned char left[20];
	SHA_CTX ctx_left;
	SHA_Init(&ctx_left);
	SHA_Update(&ctx_left, str, strlen(str));
	SHA_Final(left, &ctx_left);
	
	crypto<encode::sha::_160bit> code;	
	byte_array right = code.execute((const unsigned char*)str, strlen(str));

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(0 , !memcmp(left, &right[0], encode::sha::_160bit::BLOCK_COUNT));

	unsigned char equal[20];
	SHA_CTX ctx_equal;
	SHA1_Init(&ctx_equal);
	SHA1_Update(&ctx_equal, str, strlen(str));
	SHA1_Final(equal, &ctx_equal);

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(0, memcmp(equal, &right[0], encode::sha::_160bit::BLOCK_COUNT));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";

	crypto<encode::sha::_256bit> code1;
	byte_array right = code1.execute((const unsigned char*)str, strlen(str));

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(encode::sha::_256bit::BLOCK_COUNT, right.size());

	crypto<encode::sha::_512bit> code2;
	right = code2.execute((const unsigned char*)str, strlen(str));

	// 각 암호화 알고리즘의 블록 크기는 다음과 같은 형태로 제공한다. 기준은 bytes이다.
	BOOST_CHECK_EQUAL(encode::sha::_512bit::BLOCK_COUNT, right.size());
}

BOOST_AUTO_TEST_SUITE_END()