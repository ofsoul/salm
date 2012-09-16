#include "interface.hpp"
#include "asymmetrics.hpp"

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

using namespace salm;

#define	DEFINE_RSA_PUBMODULUS		128
#define	DEFINE_RSA_PUBEXPONENT		3
#define	DEFINE_RSA_PRIEXPONENT		128
#define	DEFINE_RSA_PRIFACTORP		64
#define	DEFINE_RSA_PRIFACTORQ		64
#define	DEFINE_RSA_DMP1				64
#define	DEFINE_RSA_DMQ1				64
#define	DEFINE_RSA_IQMP				64

struct exchange_key
{
	unsigned char	public_modulus[DEFINE_RSA_PUBMODULUS];
	unsigned char	public_exponent[DEFINE_RSA_PUBEXPONENT];
	unsigned char	private_exponent[DEFINE_RSA_PRIEXPONENT];
	unsigned char	prime_factorP[DEFINE_RSA_PRIFACTORP];
	unsigned char	prime_factorQ[DEFINE_RSA_PRIFACTORQ];
	unsigned char	dmp1[DEFINE_RSA_DMP1];
	unsigned char	dmq1[DEFINE_RSA_DMQ1];
	unsigned char	iqmp[DEFINE_RSA_IQMP];
};

BOOST_AUTO_TEST_SUITE(ORIGINAL)

BOOST_AUTO_TEST_CASE(FUNCTION_TEST)
{
	const char *planText = "Hello RSA!";
	unsigned char encrypt_buf[128];
	unsigned char decrypt_buf[32];

	//RSA ������ bit��, �Ҽ� �ʱⰪ�� ���� ��Ž� �ְ� �޾ƾ��� ����ü ũ�Ⱑ ����ȴ�.
	//�� �� ����, ���� ������ ������ ������Ų��.
	//ũ�� ������ ���ҽ� define���� �����Ͽ� �������ϸ� �ȴ�.
	RSA *rsa = RSA_generate_key(1024, 0x010001, NULL, NULL);
	BOOST_CHECK(rsa);

	//rsa�� Ŭ���� �ƴϴ�. pub�� ���� ���� ������ rsa�� ���� �ٸ���.
	RSA *pub = RSAPublicKey_dup(rsa);
	BOOST_CHECK(pub);

	//rsa�� Ŭ���� �ƴϴ�. pri�� ���� ���� ������ rsa�� ���� �ٸ���.
	RSA *pri = RSAPrivateKey_dup(rsa);
	BOOST_CHECK(pri);

	//�е��� �߰��ϴ� ����� x509�� �������� ����������, ��������� �������� ���� ���̹Ƿ� RSA_PKCS1_PADDING�� �����Ѵ�. 
	int len = RSA_public_encrypt(strlen(planText) + 1, (const unsigned char*)planText, encrypt_buf, pub, RSA_PKCS1_PADDING);

	int ret = RSA_private_decrypt(len, encrypt_buf, decrypt_buf, pri, RSA_PKCS1_PADDING);

	BOOST_CHECK_EQUAL(0, strcmp(planText, (const char*)decrypt_buf));

	RSA_free(rsa);
	RSA_free(pub);
	RSA_free(pri);
}

BOOST_AUTO_TEST_CASE(PRIVATEKEY_REPLACE_TEST)
{	
	RSA *pri = RSA_generate_key(1024, 0x010001, NULL, NULL);

	//Ű�� ��ȣ�ϴ� �������� ��ť�� ���ä���� ���� Ű��ȯ ����� �������� �����Ƿ�(�� ����� ��Ʈ��ũ ���� �������� �ʱ⶧��)
	//�� ���ĪŰ ��ȣ�� ����ڿ��� �ñ��.

	exchange_key key = {};
	//�������� ���� ���̳ʸ� ������ ��ȯ
	int ret = BN_bn2bin(pri->n, key.public_modulus);
	ret = BN_bn2bin(pri->e, key.public_exponent);
	ret = BN_bn2bin(pri->d, key.private_exponent);
	ret = BN_bn2bin(pri->p, key.prime_factorP);
	ret = BN_bn2bin(pri->q, key.prime_factorQ);
	ret = BN_bn2bin(pri->dmp1, key.dmp1);
	ret = BN_bn2bin(pri->dmq1, key.dmq1);
	ret = BN_bn2bin(pri->iqmp, key.iqmp);

	ret = BN_num_bits(pri->n);
	ret = BN_num_bits(pri->e);
	ret = BN_num_bits(pri->d);
	ret = BN_num_bits(pri->p);
	ret = BN_num_bits(pri->q);
	ret = BN_num_bits(pri->dmp1);
	ret = BN_num_bits(pri->dmq1);
	ret = BN_num_bits(pri->iqmp);

	RSA *pri_comp = RSA_new();
	//���̳ʸ� ���� �޸𸮻��� RSA�� ������ ��ȯ 
	pri_comp->n = BN_bin2bn(key.public_modulus, DEFINE_RSA_PUBMODULUS, pri_comp->n);
	pri_comp->e = BN_bin2bn(key.public_exponent, DEFINE_RSA_PUBEXPONENT, pri_comp->e);
	pri_comp->d = BN_bin2bn(key.private_exponent, DEFINE_RSA_PRIEXPONENT, pri_comp->d);
	pri_comp->p = BN_bin2bn(key.prime_factorP, DEFINE_RSA_PRIFACTORP, pri_comp->p);
	pri_comp->q = BN_bin2bn(key.prime_factorQ, DEFINE_RSA_PRIFACTORQ, pri_comp->q);
	pri_comp->dmp1 = BN_bin2bn(key.dmp1, DEFINE_RSA_DMP1, pri_comp->dmp1);
	pri_comp->dmq1 = BN_bin2bn(key.dmq1, DEFINE_RSA_DMQ1, pri_comp->dmq1);
	pri_comp->iqmp = BN_bin2bn(key.iqmp, DEFINE_RSA_IQMP, pri_comp->iqmp);

	BOOST_CHECK_EQUAL(*(pri->n->d), *(pri_comp->n->d));
	BOOST_CHECK_EQUAL(*(pri->e->d), *(pri_comp->e->d));
	BOOST_CHECK_EQUAL(*(pri->d->d), *(pri_comp->d->d));
	BOOST_CHECK_EQUAL(*(pri->p->d), *(pri_comp->p->d));
	BOOST_CHECK_EQUAL(*(pri->q->d), *(pri_comp->q->d));
	BOOST_CHECK_EQUAL(*(pri->dmp1->d), *(pri_comp->dmp1->d));
	BOOST_CHECK_EQUAL(*(pri->dmq1->d), *(pri_comp->dmq1->d));
	BOOST_CHECK_EQUAL(*(pri->iqmp->d), *(pri_comp->iqmp->d));

	RSA_free(pri_comp);
	RSA_free(pri);
}

BOOST_AUTO_TEST_CASE(PUBLICKEY_REPLACE_TEST)
{
	RSA *pub = RSA_generate_key(1024, 0x010001, NULL, NULL);

	exchange_key key = {};
	BN_bn2bin(pub->n, key.public_modulus);
	BN_bn2bin(pub->e, key.public_exponent);

	RSA *pub_comp = RSA_new();
	pub_comp->n = BN_bin2bn(key.public_modulus, DEFINE_RSA_PUBMODULUS, pub_comp->n);
	pub_comp->e = BN_bin2bn(key.public_exponent, DEFINE_RSA_PUBEXPONENT, pub_comp->e);

	BOOST_CHECK_EQUAL(*(pub->n->d), *(pub_comp->n->d));
	BOOST_CHECK_EQUAL(*(pub->e->d), *(pub_comp->e->d));

	RSA_free(pub_comp);
	RSA_free(pub);
}

BOOST_AUTO_TEST_CASE(FULL_TEST)
{
	const char *planText = "Hello RSA!";
	unsigned char encrypt_buf[128];
	unsigned char decrypt_buf[32];

	//RSA ������ bit��, �Ҽ� �ʱⰪ�� ���� ��Ž� �ְ� �޾ƾ��� ����ü ũ�Ⱑ ����ȴ�.
	//�� �� ����, ���� ������ ������ ������Ų��.
	//ũ�� ������ ���ҽ� define���� �����Ͽ� �������ϸ� �ȴ�.
	exchange_key key = {};
	RSA *rsa = RSA_generate_key(1024, 0x010001, NULL, NULL);
	BOOST_CHECK(rsa);

	//rsa�� Ŭ���� �ƴϴ�. pub�� ���� ���� ������ rsa�� ���� �ٸ���.
	//RSA *pub = RSAPublicKey_dup(rsa);
	//BOOST_CHECK(pub);
	
	BN_bn2bin(rsa->n, key.public_modulus);
	BN_bn2bin(rsa->e, key.public_exponent);
	RSA *pub_comp = RSA_new();
	pub_comp->n = BN_bin2bn(key.public_modulus, DEFINE_RSA_PUBMODULUS, pub_comp->n);
	pub_comp->e = BN_bin2bn(key.public_exponent, DEFINE_RSA_PUBEXPONENT, pub_comp->e);
	

	//�е��� �߰��ϴ� ����� x509�� �������� ����������, ��������� �������� ���� ���̹Ƿ� RSA_PKCS1_PADDING�� �����Ѵ�. 
	int len = RSA_public_encrypt(strlen(planText) + 1, (const unsigned char*)planText, encrypt_buf, pub_comp, RSA_PKCS1_PADDING);

	
	//rsa�� Ŭ���� �ƴϴ�. pri�� ���� ���� ������ rsa�� ���� �ٸ���.
	//RSA *pri = RSAPrivateKey_dup(rsa);
	//BOOST_CHECK(pri);

	memset(&key, 0x00, sizeof(key));
	//�������� ���� ���̳ʸ� ������ ��ȯ
	int ret = BN_bn2bin(rsa->n, key.public_modulus);
	ret = BN_bn2bin(rsa->e, key.public_exponent);
	ret = BN_bn2bin(rsa->d, key.private_exponent);
	ret = BN_bn2bin(rsa->p, key.prime_factorP);
	ret = BN_bn2bin(rsa->q, key.prime_factorQ);
	ret = BN_bn2bin(rsa->dmp1, key.dmp1);
	ret = BN_bn2bin(rsa->dmq1, key.dmq1);
	ret = BN_bn2bin(rsa->iqmp, key.iqmp);

	RSA *pri_comp = RSA_new();
	//���̳ʸ� ���� �޸𸮻��� RSA�� ������ ��ȯ 
	pri_comp->n = BN_bin2bn(key.public_modulus, DEFINE_RSA_PUBMODULUS, pri_comp->n);
	pri_comp->e = BN_bin2bn(key.public_exponent, DEFINE_RSA_PUBEXPONENT, pri_comp->e);
	pri_comp->d = BN_bin2bn(key.private_exponent, DEFINE_RSA_PRIEXPONENT, pri_comp->d);
	pri_comp->p = BN_bin2bn(key.prime_factorP, DEFINE_RSA_PRIFACTORP, pri_comp->p);
	pri_comp->q = BN_bin2bn(key.prime_factorQ, DEFINE_RSA_PRIFACTORQ, pri_comp->q);
	pri_comp->dmp1 = BN_bin2bn(key.dmp1, DEFINE_RSA_DMP1, pri_comp->dmp1);
	pri_comp->dmq1 = BN_bin2bn(key.dmq1, DEFINE_RSA_DMQ1, pri_comp->dmq1);
	pri_comp->iqmp = BN_bin2bn(key.iqmp, DEFINE_RSA_IQMP, pri_comp->iqmp);
	
	ret = RSA_private_decrypt(len, encrypt_buf, decrypt_buf, pri_comp, RSA_PKCS1_PADDING);

	BOOST_CHECK_EQUAL(0, strcmp(planText, (const char*)decrypt_buf));

	RSA_free(rsa);
	RSA_free(pub_comp);
	RSA_free(pri_comp);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LIBRARY)

BOOST_AUTO_TEST_CASE(NORMAL_TEST)
{
	const char *str = "ofsoul";	

	rsa::generate_key ag(encode::rsa::_1024bit::KEY_BYTES);
	crypto<encode::rsa::_1024bit> en(ag.public_key());
	byte_array encrypt_buf = en.execute((const unsigned char*)str, strlen(str));

	crypto<decode::rsa::_1024bit> de(ag.private_key());		
	byte_array decrypt_buf = de.execute(encrypt_buf);

	BOOST_CHECK_EQUAL(std::string(str), salm::bytes_to_string(decrypt_buf));
}

BOOST_AUTO_TEST_CASE(EXCEPTION_TEST)
{
	const char *str = "ofsoul";

	rsa::generate_key ag(encode::rsa::_1024bit::KEY_BYTES);

	try {
		// 1��° ���� : Ű �����Ⱑ �ٸ���.
		crypto<encode::rsa::_768bit> en(ag.public_key());
	}
	catch(salm::exception &e) {
		BOOST_CHECK_EQUAL(salm::INVALID_KEY_BYTES, e.errcode());
	}

	try {
		// 2��° ���� : �ٸ� ������ Ű�� �Է¹޾Ҵ�.
		crypto<encode::rsa::_1024bit> en(ag.private_key());
	}
	catch(salm::exception &e) {
		BOOST_CHECK_EQUAL(salm::INVALID_KEY_BYTES, e.errcode());
	}

	try {
		// 3��° ���� : Ű ������� ���� �Ѵ� �� �� �ƴ�.
		crypto<encode::rsa::_2048bit> en(ag.private_key());
	}
	catch(salm::exception &e) {
		BOOST_CHECK_EQUAL(salm::INVALID_KEY_BYTES, e.errcode());
	}	

	byte_array planbytes(118, 'a');

	crypto<encode::rsa::_1024bit> en(ag.public_key());	

	try {
		// 4��° ���� : �ִ� ������ũ��� bytes - padding(11) �̴�.
		byte_array encrypt_buf = en.execute(planbytes);
	}
	catch(salm::exception &e) {
		BOOST_CHECK_EQUAL(salm::INVALID_DATA_SIZE, e.errcode());
	}
}

BOOST_AUTO_TEST_SUITE_END()