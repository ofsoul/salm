//	���ĪŰ �˰���
//
//	����Ư¡
//    - Ű�� 2�� �����Ѵ�. (����Ű, ����Ű)
//    - ����ڰ� ���Ƿ� Ű�� ���� �� ������, Ű �����⸦ Ȱ���ؾ� �Ѵ�.
//    - ������ Ű�δ� ��ȣȭ�� �Ұ����ϸ�, �ٸ� Ű�θ� ��ȣȭ�� �� �ִ�.
//		- ���� : ����Ű�θ� ��ȣȭ�ؾ� �ϴ� ���� �ƴϴ�. ����Ű�� ��ȣȭ���� ����Ű�� ��ȣȭ�� ���� �ִ�.
//    - ��ȣȭ�� �� �ִ� �������� �ִ� ũ�� = Ű ������ - �е� ũ��� ����.
//
//	���� �˰���
//	- RSA
//
//	�������̽�
//    - ���� �ٸ� ���ĪŰ �˰����� ������ �������̽��� ���� �����ϰ� ��� �����ϴ�.
//
//	���߹��
//	- ��ȣȭ
//	
//	//������ ����
//	rsa::generate_key key_gen(encode::rsa::_1024bit::KEY_BYTES);
//		
//	//��� ���� �� �����⸦ ���� Ű�Է�
//	crypto<encode::rsa::_1024bit>		encrypt(key_gen.public_key());
//		
//	//��ȣȭ
//	byte_array dst = encrypt.execute(src, src_size));
//	
//	- ��ȣȭ
//		
//	//��� ���� �� �����⸦ ���� Ű�Է�
//	crypto<decode::rsa::_1024bit>		decrypt(key_gen.private());		
//		
//	//��ȣȭ
//	byte_array dst = decrypt.execute(src, src_size);	
//
//
//	���ҽ�
//	- openssl-1.0.1c
//
//	�����ڷ�
//    - ��ȣȭ �˰��� ���� : http://wiki.kldp.org/HOWTO/html/Secure-Programs-HOWTO/crypto.html
//    - ���ĪŰ ���� : http://en.wikipedia.org/wiki/Public-key_cryptography
#ifndef __ASYMMETRICS_HPP
#define __ASYMMETRICS_HPP

#include "asymmetrics/rsa.hpp"

namespace salm {
		
	namespace encode {

		namespace rsa {
			
			template <typename Padding> struct rsa768 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 96, 11> {};
			template <typename Padding> struct rsa1024 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 128, 11> {};
			template <typename Padding> struct rsa2048 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 256, 11> {};


			typedef rsa768<salm::rsa::PKCS1_PADDING>			_768bit;
			typedef rsa1024<salm::rsa::PKCS1_PADDING>			_1024bit;		
			typedef rsa2048<salm::rsa::PKCS1_PADDING>			_2048bit;
		}
	}

	namespace decode {

		namespace rsa {

			template <typename Padding> struct rsa768 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 96, 11> {};
			template <typename Padding> struct rsa1024 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 128, 11> {};
			template <typename Padding> struct rsa2048 : public AsymmetricBASE<Padding, RSA, salm::rsa::rsa_impl, 256, 11> {};

			typedef rsa768<salm::rsa::PKCS1_PADDING>			_768bit;
			typedef rsa1024<salm::rsa::PKCS1_PADDING>			_1024bit;		
			typedef rsa2048<salm::rsa::PKCS1_PADDING>			_2048bit;
		}		
	}	
}

#endif //__ASYMMETRICS_HPP