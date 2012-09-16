#include "salm.hpp"
#include "version.hpp"

#include <algorithm>
#include <ctime>

extern "C" {
#include "openssl/crypto.h"
}

//openssl�� rsa�ڵ��� RSA_new() �Լ����� �޸� ���� ����Ű�� �ɷ� �����ȴ�.(openssl-1.0.1c����)
//https://issues.apache.org/bugzilla/show_bug.cgi?id=45828 Ȯ���� ��.
//{	//�������� ���α׷��� �̿��ϸ� �޸𸮸��� Ȯ���� �� �ִ�.
//	RSA *rsa = RSA_new();
//	RSA_free(rsa);
//}

struct programonce {
	programonce() {
	}
	~programonce() {
		/* This function cleans up all "ex_data" state. It mustn't be called under
		* potential race-conditions. */
		//http://www.mail-archive.com/openssl-dev@openssl.org/msg17923.html
		CRYPTO_cleanup_all_ex_data();
	}
} once;

namespace salm {

	exception::exception(const char * const &str)
		: std::exception(str), _err(UNKNOWN_ERROR)
	{

	}
	exception::exception(const char * const &str, int e)
		: std::exception(str), _err(e)
	{

	}
	int exception::errcode()
	{
		return _err;
	}

	std::string bytes_to_string(const byte_array &ori)
	{
		return std::string(ori.begin(), ori.end());
	}

	byte_array string_to_bytes(const std::string &ori)
	{
		return byte_array(ori.begin(), ori.end());
	}	

	byte_array generate_bytes(std::size_t n)
	{	
		std::srand(std::time(0));
		byte_array ret; ret.resize(n);
		std::generate(ret.begin(), ret.end(), rand);
		return ret;
	}

	byte_array static_bytes(std::size_t n)
	{
		salm_dynamic_assert( 0 != n, "Zero is not" );

		std::string version_string;
		version_string += PROJECT;
		version_string += VERSION;
		version_string += REVISION;
		version_string += BUILD_NUMBER;
		version_string.resize(n, version_string.size() % n);
		return string_to_bytes(version_string);
	}
}