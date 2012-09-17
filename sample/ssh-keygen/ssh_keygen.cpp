#include "asymmetrics.hpp"
#include "transforms.hpp"

#include <fstream>

using namespace salm;

int main(int argc, char *argv[])
{
	rsa::generate_key ag(encode::rsa::_2048bit::KEY_BYTES);	

	//PKCS#1 PEM-encoded public key
	encode::base64	encoder;
	std::string banner = "ssh-rsa ";							//배너
	std::string encoding = encoder.execute(ag.public_key());	//공개키 인코딩
	std::string mark = " ofsoul@hitel.net";						//메일주소

	std::ofstream pubfile("default_rsa.pub");
	pubfile << banner << encoding << mark << std::endl;

	//PKCS#1 PEM-encoded private key
	banner = "-----BEGIN RSA PRIVATE KEY-----";					//배너
	encoding = encoder.execute(ag.private_key());				//개인키 인코딩
	mark = "-----END RSA PRIVATE KEY-----";	

	std::ofstream prifile("default_rsa.pri");
	prifile << banner << std::endl;
	prifile << encoding << std::endl;
	prifile << mark << std::endl;

	return 0;
}