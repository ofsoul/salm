#include "interface.hpp"
#include "ciphers.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(STREAM_TEST)
{
	const char *plantext = "1234567890123456";

	RABBIT_ECRYPT_ctx en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8 };
	char buf[32] = {};
	RABBIT_ECRYPT_keysetup(&en_sch, key, sizeof(key) * 8, sizeof(iv) * 8);
	RABBIT_ECRYPT_ivsetup(&en_sch, iv);
	RABBIT_ECRYPT_encrypt_bytes(&en_sch, (const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext));

	char ret[32] = {};
	RABBIT_ECRYPT_ctx de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8 };
	RABBIT_ECRYPT_keysetup(&de_sch, key, sizeof(key) * 8, sizeof(iv) * 8);
	RABBIT_ECRYPT_ivsetup(&de_sch, iv2);
	RABBIT_ECRYPT_decrypt_bytes(&de_sch, (const unsigned char*)&buf[0], (unsigned char*)ret, 16);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(STREAM_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::rabbit::_128bit::KEY_BYTES);
	crypto<encode::rabbit::_128bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::rabbit::_128bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));

	//예외 테스트	
	key = salm::string_to_bytes("key123");	
	try {
		crypto<decode::rabbit::_128bit> de2(key);
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
		crypto<encode::rabbit::_128bit> en(key);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}

	try {
		byte_array key = salm::generate_bytes(encode::rabbit::_128bit::KEY_BYTES);
		byte_array iv = salm::string_to_bytes("initialvector12345678901234567890");	
		crypto<encode::rabbit::_128bit> en(key, iv);
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

	byte_array key = salm::generate_bytes(encode::rabbit::_128bit::KEY_BYTES);
	crypto<encode::rabbit::_128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::rabbit::_128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));
}

BOOST_AUTO_TEST_SUITE_END()