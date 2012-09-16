#include "interface.hpp"
#include "ciphers.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "1234567890";		

	DES_key_schedule en_sch;
	DES_cblock key = { 1,2,3,4,5,6,7,8 };
	char buf[32] = {};
	DES_set_key_unchecked(&key, &en_sch);	
	DES_ecb_encrypt((const_DES_cblock *)plantext, (DES_cblock *)buf, &en_sch, DES_ENCRYPT);
	
	char ret[32] = {};
	DES_key_schedule de_sch;
	DES_set_key_unchecked(&key, &de_sch);
	DES_ecb_encrypt((const_DES_cblock *)&buf[0], (DES_cblock *)ret, &de_sch, DES_DECRYPT);

	//8바이트만 암호화한다.
	BOOST_CHECK_EQUAL(0, strncmp(plantext, ret, 8));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "12345678";

	DES_key_schedule en_sch;
	DES_cblock key = { 1,2,3,4,5,6,7,8 };
	DES_cblock iv = { 11,12,13,14,15,16,17,18 };
	char buf[32] = {};
	DES_set_key_unchecked(&key, &en_sch);
	DES_ncbc_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, &iv, DES_ENCRYPT);

	char ret[32] = {};
	DES_key_schedule de_sch;
	DES_cblock iv2 = { 11,12,13,14,15,16,17,18 };
	DES_set_key_unchecked(&key, &de_sch);
	DES_ncbc_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 8, &de_sch, &iv2, DES_DECRYPT);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "12345678";

	const int bits = 8;
	DES_key_schedule en_sch;
	DES_cblock key = { 1,2,3,4,5,6,7,8 };
	DES_cblock iv = { 11,12,13,14,15,16,17,18 };
	char buf[32] = {};
	DES_set_key_unchecked(&key, &en_sch);	
	DES_cfb_encrypt((const unsigned char*)plantext, (unsigned char*)buf, bits, strlen(plantext), &en_sch, &iv, DES_ENCRYPT);

	char ret[32] = {};
	DES_key_schedule de_sch;
	DES_cblock iv2 = { 11,12,13,14,15,16,17,18 };
	DES_set_key_unchecked(&key, &de_sch);
	DES_cfb_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, bits, 8, &de_sch, &iv2, DES_DECRYPT);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678";

	const int bits = 8;
	DES_key_schedule en_sch;
	DES_cblock key = { 1,2,3,4,5,6,7,8 };
	DES_cblock iv = { 11,12,13,14,15,16,17,18 };
	char buf[32] = {};
	DES_set_key_unchecked(&key, &en_sch);	
	DES_ofb_encrypt((const unsigned char*)plantext, (unsigned char*)buf, bits, strlen(plantext), &en_sch, &iv);

	char ret[32] = {};
	DES_key_schedule de_sch;
	DES_cblock iv2 = { 11,12,13,14,15,16,17,18 };
	DES_set_key_unchecked(&key, &de_sch);
	DES_ofb_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, bits, 8, &de_sch, &iv2);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "12345678";
	byte_array key = salm::generate_bytes(encode::des::_ECB64bit::KEY_BYTES);	

	crypto<encode::des::_ECB64bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));
	
	crypto<decode::des::_ECB64bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::des::CBC64<salm::padding::ANSIX923>::KEY_BYTES);
	crypto<encode::des::CBC64<salm::padding::ANSIX923>> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));
	
	crypto<decode::des::CBC64<salm::padding::ANSIX923>> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));

	//예외 테스트	
	key = salm::string_to_bytes("key123");	
	try {
		crypto<encode::des::CBC64<salm::padding::ANSIX923>> de2(key);
	}
	catch(salm::exception &e) {
		BOOST_CHECK(true);
	}
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::des::_CFB64bit::KEY_BYTES);
	crypto<encode::des::_CFB64bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::des::_CFB64bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::des::_OFB64bit::KEY_BYTES);
	crypto<encode::des::_OFB64bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::des::_OFB64bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(EXCEPTION_TEST)
{
	const char *plantext = "1234";		

	try {
		byte_array key = salm::string_to_bytes("key12345678901234567890");
		crypto<encode::des::_CBC64bit> en(key);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}

	try {
		byte_array key = salm::generate_bytes(encode::des::_CBC64bit::KEY_BYTES);
		byte_array iv = salm::string_to_bytes("initialvector12345678901234567890");	
		crypto<encode::des::_CBC64bit> en(key, iv);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_IV_BYTES);
	}

	try {		
		crypto<encode::des::CBC64<salm::padding::NONE>> en;
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

	byte_array key = salm::string_to_bytes("12345678");
	crypto<encode::des::_ECB64bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::des::_ECB64bit> de(key);
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

	byte_array key = salm::string_to_bytes("12345678");
	crypto<encode::des::_CBC64bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::des::_CBC64bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//CBC는 KEYSTREAM이 적용된다.
	try 
	{
		byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	}
	catch(salm::exception &e)
	{
		BOOST_CHECK(true);
	}	
}

BOOST_AUTO_TEST_CASE(CFB_KEYSTREAM_TEST)
{
	const char *plantext1 = "ofsoul1234";
	const char *plantext2 = "ofsoul2456";

	byte_array key = salm::string_to_bytes("12345678");
	crypto<encode::des::_CFB64bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::des::_CFB64bit> de(key);
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

	byte_array key = salm::string_to_bytes("12345678");
	crypto<encode::des::_OFB64bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::des::_OFB64bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//OFB는 KEYSTREAM이 적용된다.
	byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf3));
}

BOOST_AUTO_TEST_SUITE_END()