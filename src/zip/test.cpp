#include "interface.hpp"
#include "compressions.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *planText = "ofsoul123";

	char encrypt_buf[32];
	char decrypt_buf[32];

	memset(encrypt_buf, 0, sizeof(encrypt_buf));
	memset(decrypt_buf, 0, sizeof(decrypt_buf));
	
	uLong src_size = ::compressBound(strlen(planText) + 1);
	::compress((Bytef*)encrypt_buf, &src_size, (const Bytef*)planText, strlen(planText) + 1);

	uLong dst_size = sizeof(decrypt_buf);
	::uncompress((Bytef*)decrypt_buf, &dst_size, (const Bytef*)encrypt_buf, src_size);

	BOOST_CHECK_EQUAL(0, strcmp(planText, decrypt_buf));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)
BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *planText = "ofsoul12345";	

	crypto<encode::zip> en;
	byte_array encrypt_buf = en.execute((const unsigned char*)planText, strlen(planText));

	crypto<decode::zip> de;
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(planText), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(APPLICATION)

BOOST_AUTO_TEST_CASE(BIGDATA_TEST)
{
	std::string planText(4096, 'a');

	crypto<encode::zip> en;
	byte_array encrypt_buf = en.execute(salm::string_to_bytes(planText));

	crypto<decode::zip> de;
	byte_array decrypt_buf = de.execute(encrypt_buf);
	
	BOOST_CHECK_EQUAL(planText.size(), decrypt_buf.size());
	BOOST_CHECK_EQUAL(planText, salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_SUITE_END()