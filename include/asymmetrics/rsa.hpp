//레퍼런스
//- openssl : http://www.openssl.org/docs/crypto/rsa.html#
//- wikipedia : http://en.wikipedia.org/wiki/RSA
#ifndef __RSA_HPP
#define __RSA_HPP

#include "salm.hpp"
#include "asymmetric.hpp"

extern "C" {
#include "openssl/rsa.h"
#include "openssl/bn.h"
}

/* http://www.nabble.com/RSA-library-and-block-size-td10964867.html#a10964867
	key lenght block size available space
	2048 bit 256 byte 245 byte
	1024 bit 128 byte 117 byte
	768 bit 96 byte 85
*/

namespace salm {

	namespace rsa {

		//! 이 모듈의 소수값은 정해져있다. 변경가능하지만, 소수여야 한다.
		const std::size_t ODD_NUMBER = 0x010001;
		
		//! openssl에 정의된 값. RSA PKCS1 PADDING으로 블록사이즈는 11
		struct PKCS1_PADDING
		{
			enum { value = RSA_PKCS1_PADDING, };
		};

		//! openssl에 정의된 값. RSA SSLV23 PADDING으로 블록사이즈는 11
		struct SSLV23_PADDING
		{
			enum { value = RSA_SSLV23_PADDING, };
		};

		// openssl에 정의된 값. 패딩이 없을시는 블록사이즈를 0으로 해야한다.
		// 사용자가 실수할 여지가 있으므로, 일단 제외
		//struct NO_PADDING
		//{
		//	enum { value = RSA_NO_PADDING, };
		//};

		//! openssl에 정의된 값. RSA PKCS1 OAEP PADDING으로 블록사이즈는 11
		struct PKCS1_OAEP_PADDING
		{
			enum { value = RSA_PKCS1_OAEP_PADDING, };
		};

		//! openssl에 정의된 값. RSA X931 PADDING으로 블록사이즈는 11
		struct X931_PADDING
		{
			enum { value = RSA_X931_PADDING, };
		};

		// rsa 구현부
		struct rsa_impl
		{
			typedef byte_array		encrypt_input_type;
			typedef byte_array		encrypt_output_type;
			typedef byte_array		decrypt_input_type;
			typedef byte_array		decrypt_output_type;

			typedef byte_array		public_key_type;
			typedef byte_array		private_key_type;

			typedef EMPTY			iv_type;

			/*! \brief 공개키 초기화
			*
			*	\param hint 공개키 바이트
			*	\param key_bytes 키의 크기
			*	\retval RSA* 라이브러리 내부에서 처리하는 키 구조체
			*	\exception INVALID_KEY_BYTES 키 크기가 다를시 예외를 리턴한다.
			*	\remark 키 크기를 통해 공개키인지 개인키인지 확인한다.
			*			공개키와 개인키는 동일한 키 생성기 것이어야 한다.			
			*/
			RSA* init_encrypt_key(const public_key_type &hint, std::size_t key_bytes)
			{	
				const std::size_t PUBMODULUS = key_bytes;
				const std::size_t PUBEXPONENT = 3;

				if (hint.size() != PUBMODULUS + PUBEXPONENT)	
					throw salm::exception("Is not equal to a fixed public key size", salm::INVALID_KEY_BYTES);

				RSA *en_sch = RSA_new();

				std::size_t pos = 0;
				en_sch->n = BN_bin2bn(&hint[pos], PUBMODULUS, en_sch->n);		pos += PUBMODULUS;
				en_sch->e = BN_bin2bn(&hint[pos], PUBEXPONENT, en_sch->e);		pos += PUBEXPONENT;

				return en_sch;
			}			

			/*! \brief 개인키 초기화
			*
			*	\param hint 개인키 바이트
			*	\param key_bytes 키의 크기
			*	\retval RSA* 라이브러리 내부에서 처리하는 키 구조체
			*	\exception INVALID_KEY_BYTES 키 크기가 다를시 예외를 리턴한다.
			*	\remark 키 크기를 통해 공개키인지 개인키인지 확인한다.
			*			공개키와 개인키는 동일한 키 생성기 것이어야 한다.
			*/
			RSA* init_decrypt_key(const private_key_type &hint, std::size_t key_bytes)
			{				
				const std::size_t PUBMODULUS = key_bytes;
				const std::size_t PUBEXPONENT = 3;
				const std::size_t PRIEXPONENT = key_bytes;
				const std::size_t PRIFACTORP = key_bytes / 2;
				const std::size_t PRIFACTORQ = key_bytes / 2;
				const std::size_t DMP1 = key_bytes / 2;
				const std::size_t DMQ1 = key_bytes / 2;
				const std::size_t IQMP = key_bytes / 2;

				if (hint.size() != PUBMODULUS + PUBEXPONENT + PRIEXPONENT + PRIFACTORP + PRIFACTORQ + DMP1 + DMQ1 + IQMP)	
					throw salm::exception("Is not equal to a fixed private key size", salm::INVALID_KEY_BYTES);

				RSA *de_sch = RSA_new();

				std::size_t pos = 0;
				de_sch->n = BN_bin2bn(&hint[pos], PUBMODULUS, de_sch->n);		pos += PUBMODULUS;
				de_sch->e = BN_bin2bn(&hint[pos], PUBEXPONENT, de_sch->e);		pos += PUBEXPONENT;
				de_sch->d = BN_bin2bn(&hint[pos], PRIEXPONENT, de_sch->d);		pos += PRIEXPONENT;
				de_sch->p = BN_bin2bn(&hint[pos], PRIFACTORP, de_sch->p);		pos += PRIFACTORP;
				de_sch->q = BN_bin2bn(&hint[pos], PRIFACTORQ, de_sch->q);		pos += PRIFACTORQ;
				de_sch->dmp1 = BN_bin2bn(&hint[pos], DMP1, de_sch->dmp1);		pos += DMP1;
				de_sch->dmq1 = BN_bin2bn(&hint[pos], DMQ1, de_sch->dmq1);		pos += DMQ1;
				de_sch->iqmp = BN_bin2bn(&hint[pos], IQMP, de_sch->iqmp);		pos += IQMP; 
				return de_sch;
			}

			void release_encrypt_key(RSA *key)
			{	
				RSA_free(key);
			}

			void release_decrypt_key(RSA *key)
			{	
				RSA_free(key);
			}

			/*! \brief 공개키 암호화
			*
			*	\param dst 사용자 버퍼
			*	\param src 암호화할 내용
			*	\param RSA* 라이브러리 내부에서 처리하는 키 구조체
			*	\remark 패딩방식은 template Padding을 통해 구현한다.
			*/
			template <typename Padding>
			void public_encrypt(encrypt_output_type &dst, const encrypt_input_type &src, RSA *key)
			{
				::RSA_public_encrypt(src.size(), &src[0], &dst[0], key, Padding::value);
			}

			/*! \brief 개인키 복호화
			*
			*	\param dst 사용자 버퍼
			*	\param src 복호화할 내용
			*	\param RSA* 라이브러리 내부에서 처리하는 키 구조체
			*	\exception UNKNOWN_ERROR openssl에서 에러를 리턴함, 이유불명
			*	\remark 패딩방식은 template Padding을 통해 구현한다.
			*/
			template <typename Padding>
			void private_decrypt(decrypt_output_type &dst, const decrypt_input_type &src, RSA *key)
			{
				int ret = RSA_private_decrypt(src.size(), &src[0], &dst[0], key, Padding::value);
				if (0 > ret)	throw salm::exception("RSA library error", salm::UNKNOWN_ERROR);
				dst.resize(ret);
			}
		};		

		// rsa 키생성기
		// 다른 알고리즘과는 다르게, 비대칭 알고리즘은 키 생성기를 통해 키를 받아아야한다.
		// 키 생성기마다 public / private의 비대칭 키쌍을 가진다. 같은 키 생성기에서 생성한 키쌍만이 서로를 풀거나 묶을 수 있다.
		// 주의할 점은 이 키가 항상 같은 값을 가지는 것은 아니라는 것이다.
		struct generate_key
		{
			/*! \brief 생성자
			*
			*	\param bytes 키의 크기
			*	\remark 키의 크기는 0일 수 없다.
			*	\exception UNKNOWN_ERROR openssl에서 에러를 리턴함, 이유불명
			*/
			explicit generate_key(std::size_t bytes) : _sch(0), _key_bytes(bytes)
			{
				salm_dynamic_assert( 0 != _key_bytes, "key size is not zero" );

				if(!(_sch = RSA_generate_key(_key_bytes * 8, ODD_NUMBER, NULL, NULL))) 
					throw salm::exception("RSA library error", salm::UNKNOWN_ERROR);				
			}

			~generate_key()
			{
				if(_sch)	RSA_free(_sch);
			}

			/*! \brief 개인키 생성
			*
			*	\remark 키 생성기에서 개인키를 내보낸다.
			*/
			rsa_impl::private_key_type private_key()
			{
				const std::size_t PUBMODULUS = _key_bytes;
				const std::size_t PUBEXPONENT = 3;
				const std::size_t PRIEXPONENT = _key_bytes;
				const std::size_t PRIFACTORP = _key_bytes / 2;
				const std::size_t PRIFACTORQ = _key_bytes / 2;
				const std::size_t DMP1 = _key_bytes / 2;
				const std::size_t DMQ1 = _key_bytes / 2;
				const std::size_t IQMP = _key_bytes / 2;

				rsa_impl::private_key_type key;
				key.resize(PUBMODULUS + PUBEXPONENT + PRIEXPONENT + PRIFACTORP + PRIFACTORQ + DMP1 + DMQ1 + IQMP);

				// 계속 다른 바이너리 값을 리턴한다.
				// 하지만, 이 키는 같은 생성기에서 public 키로 암호화한 값을 복호화할 수 있다.
				// 키는 바이너리 배열이다.
				std::size_t pos = 0;
				BN_bn2bin(_sch->n, &key[pos]);		pos += PUBMODULUS;
				BN_bn2bin(_sch->e, &key[pos]);		pos += PUBEXPONENT;
				BN_bn2bin(_sch->d, &key[pos]);		pos += PRIEXPONENT;
				BN_bn2bin(_sch->p, &key[pos]);		pos += PRIFACTORP;
				BN_bn2bin(_sch->q, &key[pos]);		pos += PRIFACTORQ;
				BN_bn2bin(_sch->dmp1, &key[pos]);	pos += DMP1;
				BN_bn2bin(_sch->dmq1, &key[pos]);	pos += DMQ1;
				BN_bn2bin(_sch->iqmp, &key[pos]);	pos += IQMP; 

				return key;
			}

			/*! \brief 공개키 생성
			*
			*	\remark 키 생성기에서 공개키를 내보낸다.
			*/
			rsa_impl::public_key_type public_key()
			{
				const std::size_t PUBMODULUS = _key_bytes;
				const std::size_t PUBEXPONENT = 3;

				rsa_impl::public_key_type key;
				key.resize(PUBMODULUS + PUBEXPONENT);

				// 계속 다른 바이너리 값을 리턴한다.
				// 하지만, 이 키로 암호화하면 같은 생성기에서 private 키로 복호화할 수 있다.
				// 키는 바이너리 배열이다.
				std::size_t pos = 0;
				BN_bn2bin(_sch->n, &key[pos]);		pos += PUBMODULUS;
				BN_bn2bin(_sch->e, &key[pos]);		pos += PUBEXPONENT;

				return key;
			}

		private:
			//키를 내장하고 있으므로, 복사해서는 안 된다. 새로 생성할 것.
			generate_key(const generate_key &rhs);
			generate_key operator = (const generate_key &rhs);

			RSA				*_sch;
			std::size_t		_key_bytes;
		};		
	}
}

#endif //__RSA_HPP