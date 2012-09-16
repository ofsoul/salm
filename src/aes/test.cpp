#include "interface.hpp"
#include "ciphers.hpp"

#include "openssl/evp.h"
#include "openssl/aes.h"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

BOOST_AUTO_TEST_SUITE(ORIGINAL)

//BOOST_AUTO_TEST_CASE(OPENSSL)
//{
//	EVP_CIPHER_CTX en, de;
//
//	const char *plantext = "1234567890123456";
//
//	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
//	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
//	
//	EVP_CIPHER_CTX_init(&en);
//	EVP_DecryptInit_ex(&en, EVP_aes_256_cfb(), NULL, key, iv);
//	
//	unsigned char buf[32];
//	int c_len = strlen(plantext) + AES_BLOCK_SIZE, f_len = 0;
//	int len = strlen(plantext);
//	EVP_DecryptUpdate(&en, buf, &c_len, (unsigned char*)plantext, len);
//	EVP_DecryptFinal_ex(&en, buf+c_len, &f_len);
//}

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "1234567890123456";

	AES_KEY en_sch = {};
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char key2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	char buf[32] = {};
	AES_set_encrypt_key(key, 128, &en_sch);
	AES_ecb_encrypt((const unsigned char*)plantext, (unsigned char*)buf, &en_sch, 1);

	//crypto<cipher::aes::ECB256>	test((const byte*)key2, sizeof(key2));
	//byte_array e = test.execute((const unsigned char*)plantext, strlen(plantext));	

	char ret[32] = {};
	AES_KEY de_sch;
	AES_set_decrypt_key(key, 16 * 8, &de_sch);
	AES_ecb_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, &de_sch, 0);

	//16바이트만 암호화한다.
	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "1234567890123456";

	AES_KEY en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	AES_set_encrypt_key(key, 16 * 8, &en_sch);
	AES_cbc_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, 1);

	char ret[32] = {};
	AES_KEY de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	AES_set_decrypt_key(key, 16 * 8, &de_sch);
	AES_cbc_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 16, &de_sch, iv2, 0);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));	
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "12345678901234567";

	int bits = 1;
	AES_KEY en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	AES_set_encrypt_key(key, 32 * 8, &en_sch);
	AES_cfb8_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, &bits, 1);

	int bits2 = 1;
	char ret[32] = {};
	AES_KEY de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	AES_set_encrypt_key(key, 32 * 8, &de_sch);
	AES_cfb8_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 17, &de_sch, iv2, &bits2, 0);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678901234567";

	int bits = 0;
	AES_KEY en_sch;
	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char buf[32] = {};
	AES_set_encrypt_key(key, 16 * 8, &en_sch);
	AES_ofb128_encrypt((const unsigned char*)plantext, (unsigned char*)buf, strlen(plantext), &en_sch, iv, &bits);

	int bits2 = 0;
	char ret[32] = {};
	AES_KEY de_sch;
	unsigned char iv2[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	AES_set_encrypt_key(key, 16 * 8, &de_sch);
	AES_ofb128_encrypt((const unsigned char*)&buf[0], (unsigned char*)ret, 17, &de_sch, iv2, &bits2);

	BOOST_CHECK_EQUAL(0, strcmp(plantext, ret));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(ECB_TEST)
{
	const char *plantext = "12345678";	

	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };

	crypto<encode::aes::_ECB256bit> en(key, sizeof(key));
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::aes::_ECB256bit> de(key, sizeof(key));
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(CBC_TEST)
{
	const char *plantext = "12345678";

	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

	//byte_array key = salm::generate_bytes(encode::aes::CBC128<salm::padding::ANSIX923>::KEY_BYTES);
	crypto<encode::aes::CBC256<salm::padding::ISO10126>> en(key, sizeof(key), iv, sizeof(iv));
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::aes::CBC256<salm::padding::ISO10126>> de(key, sizeof(key), iv, sizeof(iv));
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));

	////예외 테스트	
	//key = salm::string_to_bytes("key123");	
	//try {
	//	crypto<decode::aes::CBC128<salm::padding::ANSIX923>> de2(key);
	//}
	//catch(salm::exception &e) {
	//	BOOST_CHECK(true);
	//}
}

BOOST_AUTO_TEST_CASE(CFB_TEST)
{
	const char *plantext = "1234567891011";

	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	unsigned char iv[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

	//byte_array key = salm::generate_bytes(cipher::aes::CFB128::KEY_SIZE);	
	crypto<encode::aes::_CFB256bit> en(key, sizeof(key), iv, sizeof(iv));
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::aes::_CFB256bit> de(key, sizeof(key), iv, sizeof(iv));
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(OFB_TEST)
{
	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::aes::_OFB128bit::KEY_BYTES);
	crypto<encode::aes::_OFB128bit> en(key);
	byte_array encrypt_buf = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::aes::_OFB128bit> de(key);
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(plantext), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(EXCEPTION_TEST)
{
	const char *plantext = "1234";		

	try {
		byte_array key = salm::string_to_bytes("key12345678901234567890");
		crypto<encode::aes::CBC128<salm::padding::Zeros>> en(key);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_KEY_BYTES);
	}

	try {
		byte_array key = salm::generate_bytes(encode::aes::CBC128<salm::padding::Zeros>::KEY_BYTES);
		byte_array iv = salm::string_to_bytes("initialvector12345678901234567890");	
		crypto<encode::aes::CBC128<salm::padding::Zeros>> en(key, iv);
	}
	catch (salm::exception &e) {
		BOOST_CHECK_EQUAL(e.errcode(), salm::INVALID_IV_BYTES);
	}

	try {		
		crypto<encode::aes::CBC128<salm::padding::NONE>> en;
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
	crypto<encode::aes::_ECB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::aes::_ECB128bit> de(key);
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
	crypto<encode::aes::CBC128<salm::padding::ANSIX923>> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::aes::CBC128<salm::padding::ANSIX923>> de(key);
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
	crypto<encode::aes::_CFB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::aes::_CFB128bit> de(key);
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
	crypto<encode::aes::_OFB128bit> en(key);

	byte_array encrypt_buf1 = en.execute((byte const*)plantext1, strlen(plantext1));
	byte_array encrypt_buf2 = en.execute((byte const*)plantext2, strlen(plantext2));

	crypto<decode::aes::_OFB128bit> de(key);
	byte_array decrypt_buf1 = de.execute(encrypt_buf1);
	byte_array decrypt_buf2 = de.execute(encrypt_buf2);

	BOOST_CHECK_EQUAL(std::string(plantext1), salm::bytes_to_string(decrypt_buf1));
	BOOST_CHECK_EQUAL(std::string(plantext2), salm::bytes_to_string(decrypt_buf2));

	//OFB는 KEYSTREAM이 적용된다.
	//byte_array decrypt_buf3 = de.execute(encrypt_buf2);
	//BOOST_CHECK_EQUAL(0, !strcmp(plantext2, (const char*)&decrypt_buf3[0]));
}

BOOST_AUTO_TEST_SUITE_END()