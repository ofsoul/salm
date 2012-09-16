#include "interface.hpp"
#include "ciphers.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(STREAM_TEST)
{
	const char *plantext = "1234567890123456";

	RC4_KEY en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	RC4_set_key(&en_sch, sizeof(key), key);
	RC4(&en_sch, strlen(plantext), (const unsigned char*)plantext, (unsigned char*)buf);

	char ret[32] = {};
	RC4_KEY de_sch;
	RC4_set_key(&de_sch, sizeof(key), key);
	RC4(&de_sch, 16, (const unsigned char*)&buf[0], (unsigned char*)ret);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(STREAM_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::rc4::_128bit::KEY_BYTES);
	crypto<encode::rc4::_128bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::rc4::_128bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));

	//예외 테스트	
	key = salm::string_to_bytes("key123");
	try {
		crypto<decode::rc4::_128bit> de2(key);
	}
	catch(salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}
}

BOOST_AUTO_TEST_CASE(EXCEPTION_TEST)
{
	const char *plantext = "1234";		

	try {
		byte_array key = salm::string_to_bytes("key12345678901234567890");
		crypto<encode::rc4::_128bit> en(key);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}

	try {
		byte_array key = salm::generate_bytes(encode::rc4::_128bit::KEY_BYTES);
		byte_array iv = salm::string_to_bytes("initialvector12345678901234567890");	
		crypto<encode::rc4::_128bit> en(key, iv);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_IV_BYTES);
	}
}

BOOST_AUTO_TEST_SUITE_END()

	BOOST_AUTO_TEST_SUITE(APPLICATION)

	BOOST_AUTO_TEST_CASE(KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul12";
	const char *plantext2 = "ofsoul2";

	byte_array key = salm::generate_bytes(encode::rc4::_128bit::KEY_BYTES);
	crypto<encode::rc4::_128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::rc4::_128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));
}

BOOST_AUTO_TEST_SUITE_END()