#include "interface.hpp"
#include "ciphers.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "1234567890123456";		

	SEED_KEY_SCHEDULE en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	SEED_set_key(key, &en_sch);	
	SEED_ecb_encrypt((const unsigned char*)plantext, (unsigned char*)buf, &en_sch, 1);

	char ret[32] = {};
	SEED_KEY_SCHEDULE de_sch;
	SEED_set_key(key, &de_sch);
	SEED_ecb_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, &de_sch, 0);

	//16바이트만 암호화한다.
	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "1234567890123456";

	SEED_KEY_SCHEDULE en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	SEED_set_key(key, &en_sch);
	SEED_cbc_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, 1);

	char ret[32] = {};
	SEED_KEY_SCHEDULE de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	SEED_set_key(key, &de_sch);
	SEED_cbc_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 16, &de_sch, iv2, 0);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "12345678";

	int bits = 8;
	SEED_KEY_SCHEDULE en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	SEED_set_key(key, &en_sch);
	SEED_cfb128_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, &bits, 1);

	int bits2 = 8;
	char ret[32] = {};
	SEED_KEY_SCHEDULE de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	SEED_set_key(key, &de_sch);
	SEED_cfb128_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 8, &de_sch, iv2, &bits2, 0);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678";

	int bits = 8;
	SEED_KEY_SCHEDULE en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	SEED_set_key(key, &en_sch);
	SEED_ofb128_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, &bits);

	int bits2 = 8;
	char ret[32] = {};
	SEED_KEY_SCHEDULE de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	SEED_set_key(key, &de_sch);
	SEED_ofb128_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 8, &de_sch, iv2, &bits2);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "12345678";
	byte_array key = salm::generate_bytes(encode::seed::_ECB128bit::KEY_BYTES);

	crypto<encode::seed::_ECB128bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::seed::_ECB128bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::seed::CBC128<salm::padding::ANSIX923>::KEY_BYTES);
	crypto<encode::seed::CBC128<salm::padding::ANSIX923>> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::seed::CBC128<salm::padding::ANSIX923>> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::seed::CFB128<salm::padding::ISO10126>::KEY_BYTES);
	crypto<encode::seed::CFB128<salm::padding::ISO10126>> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::seed::CFB128<salm::padding::ISO10126>> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::seed::_OFB128bit::KEY_BYTES);
	crypto<encode::seed::_OFB128bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::seed::_OFB128bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(EXCEPTION_TEST)
{
	const char *plantext = "1234";		

	try {
		byte_array key = salm::string_to_bytes("key12345678901234567890");
		crypto<encode::seed::CBC128<salm::padding::Zeros>> en(key);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}

	try {
		byte_array key = salm::generate_bytes(encode::seed::CBC128<salm::padding::Zeros>::KEY_BYTES);
		byte_array iv = salm::string_to_bytes("initialvector12345678901234567890");	
		crypto<encode::seed::CBC128<salm::padding::Zeros>> en(key, iv);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_IV_BYTES);
	}

	try {		
		crypto<encode::seed::CBC128<salm::padding::NONE>> en;
		byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_BAD_MULTIPLE);
	}
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(APPLICATION)

BOOST_AUTO_TEST_CASE(ECB_KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul1";
	const char *plantext2 = "ofsoul2";

	byte_array key = salm::string_to_bytes("1234567890123456");
	crypto<encode::seed::_ECB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::seed::_ECB128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//ECB는 KEYSTREAM이 적용되지 않는다!
	byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf3));	
}

BOOST_AUTO_TEST_CASE(CBC_KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul12";
	const char *plantext2 = "ofsoul2";

	byte_array key = salm::string_to_bytes("1234567890123456");
	crypto<encode::seed::CBC128<salm::padding::ANSIX923>> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::seed::CBC128<salm::padding::ANSIX923>> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//CBC는 KEYSTREAM이 적용된다.
	try 
	{
		byte_array decrypt_buf3 = de.execute(encrypt_buf2);		
	}
	catch (salm::exception &e) {
		BOOST_CHECK(true);
	}	
}

BOOST_AUTO_TEST_CASE(CFB_KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul1234";
	const char *plantext2 = "ofsoul2456";

	byte_array key = salm::string_to_bytes("1234567890123456");
	crypto<encode::seed::_CFB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::seed::_CFB128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//CFB는 KEYSTREAM이 적용된다.
	byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf3));
}

BOOST_AUTO_TEST_CASE(OFB_KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul1234";
	const char *plantext2 = "ofsoul2456";

	byte_array key = salm::string_to_bytes("1234567890123456");
	crypto<encode::seed::_OFB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::seed::_OFB128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//OFB는 KEYSTREAM이 적용된다.
	byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf3));
}

BOOST_AUTO_TEST_SUITE_END()