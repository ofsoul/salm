//	비대칭키 알고리즘
//
//	공통특징
//    - 키가 2개 존재한다. (공개키, 개인키)
//    - 사용자가 임의로 키를 만들 수 없으며, 키 생성기를 활용해야 한다.
//    - 동일한 키로는 복호화가 불가능하며, 다른 키로만 복호화할 수 있다.
//		- 참고 : 공개키로만 암호화해야 하는 것은 아니다. 개인키로 암호화한후 공개키로 복호화할 수도 있다.
//    - 암호화할 수 있는 데이터의 최대 크기 = 키 사이즈 - 패딩 크기와 같다.
//
//	지원 알고리즘
//	- RSA
//
//	인터페이스
//    - 서로 다른 비대칭키 알고리즘은 다음의 인터페이스를 통해 동일하게 사용 가능하다.
//
//	개발방법
//	- 암호화
//	
//	//생성기 생성
//	rsa::generate_key key_gen(encode::rsa::_1024bit::KEY_BYTES);
//		
//	//모듈 생성 및 생성기를 통해 키입력
//	crypto<encode::rsa::_1024bit>		encrypt(key_gen.public_key());
//		
//	//암호화
//	byte_array dst = encrypt.execute(src, src_size));
//	
//	- 복호화
//		
//	//모듈 생성 및 생성기를 통해 키입력
//	crypto<decode::rsa::_1024bit>		decrypt(key_gen.private());		
//		
//	//복호화
//	byte_array dst = decrypt.execute(src, src_size);	
//
//
//	리소스
//	- openssl-1.0.1c
//
//	참고자료
//    - 암호화 알고리즘 설명 : http://wiki.kldp.org/HOWTO/html/Secure-Programs-HOWTO/crypto.html
//    - 비대칭키 설명 : http://en.wikipedia.org/wiki/Public-key_cryptography
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