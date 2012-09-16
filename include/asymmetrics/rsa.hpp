//���۷���
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

		//! �� ����� �Ҽ����� �������ִ�. ���氡��������, �Ҽ����� �Ѵ�.
		const std::size_t ODD_NUMBER = 0x010001;
		
		//! openssl�� ���ǵ� ��. RSA PKCS1 PADDING���� ��ϻ������ 11
		struct PKCS1_PADDING
		{
			enum { value = RSA_PKCS1_PADDING, };
		};

		//! openssl�� ���ǵ� ��. RSA SSLV23 PADDING���� ��ϻ������ 11
		struct SSLV23_PADDING
		{
			enum { value = RSA_SSLV23_PADDING, };
		};

		// openssl�� ���ǵ� ��. �е��� �����ô� ��ϻ���� 0���� �ؾ��Ѵ�.
		// ����ڰ� �Ǽ��� ������ �����Ƿ�, �ϴ� ����
		//struct NO_PADDING
		//{
		//	enum { value = RSA_NO_PADDING, };
		//};

		//! openssl�� ���ǵ� ��. RSA PKCS1 OAEP PADDING���� ��ϻ������ 11
		struct PKCS1_OAEP_PADDING
		{
			enum { value = RSA_PKCS1_OAEP_PADDING, };
		};

		//! openssl�� ���ǵ� ��. RSA X931 PADDING���� ��ϻ������ 11
		struct X931_PADDING
		{
			enum { value = RSA_X931_PADDING, };
		};

		// rsa ������
		struct rsa_impl
		{
			typedef byte_array		encrypt_input_type;
			typedef byte_array		encrypt_output_type;
			typedef byte_array		decrypt_input_type;
			typedef byte_array		decrypt_output_type;

			typedef byte_array		public_key_type;
			typedef byte_array		private_key_type;

			typedef EMPTY			iv_type;

			/*! \brief ����Ű �ʱ�ȭ
			*
			*	\param hint ����Ű ����Ʈ
			*	\param key_bytes Ű�� ũ��
			*	\retval RSA* ���̺귯�� ���ο��� ó���ϴ� Ű ����ü
			*	\exception INVALID_KEY_BYTES Ű ũ�Ⱑ �ٸ��� ���ܸ� �����Ѵ�.
			*	\remark Ű ũ�⸦ ���� ����Ű���� ����Ű���� Ȯ���Ѵ�.
			*			����Ű�� ����Ű�� ������ Ű ������ ���̾�� �Ѵ�.			
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

			/*! \brief ����Ű �ʱ�ȭ
			*
			*	\param hint ����Ű ����Ʈ
			*	\param key_bytes Ű�� ũ��
			*	\retval RSA* ���̺귯�� ���ο��� ó���ϴ� Ű ����ü
			*	\exception INVALID_KEY_BYTES Ű ũ�Ⱑ �ٸ��� ���ܸ� �����Ѵ�.
			*	\remark Ű ũ�⸦ ���� ����Ű���� ����Ű���� Ȯ���Ѵ�.
			*			����Ű�� ����Ű�� ������ Ű ������ ���̾�� �Ѵ�.
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

			/*! \brief ����Ű ��ȣȭ
			*
			*	\param dst ����� ����
			*	\param src ��ȣȭ�� ����
			*	\param RSA* ���̺귯�� ���ο��� ó���ϴ� Ű ����ü
			*	\remark �е������ template Padding�� ���� �����Ѵ�.
			*/
			template <typename Padding>
			void public_encrypt(encrypt_output_type &dst, const encrypt_input_type &src, RSA *key)
			{
				::RSA_public_encrypt(src.size(), &src[0], &dst[0], key, Padding::value);
			}

			/*! \brief ����Ű ��ȣȭ
			*
			*	\param dst ����� ����
			*	\param src ��ȣȭ�� ����
			*	\param RSA* ���̺귯�� ���ο��� ó���ϴ� Ű ����ü
			*	\exception UNKNOWN_ERROR openssl���� ������ ������, �����Ҹ�
			*	\remark �е������ template Padding�� ���� �����Ѵ�.
			*/
			template <typename Padding>
			void private_decrypt(decrypt_output_type &dst, const decrypt_input_type &src, RSA *key)
			{
				int ret = RSA_private_decrypt(src.size(), &src[0], &dst[0], key, Padding::value);
				if (0 > ret)	throw salm::exception("RSA library error", salm::UNKNOWN_ERROR);
				dst.resize(ret);
			}
		};		

		// rsa Ű������
		// �ٸ� �˰������ �ٸ���, ���Ī �˰����� Ű �����⸦ ���� Ű�� �޾ƾƾ��Ѵ�.
		// Ű �����⸶�� public / private�� ���Ī Ű���� ������. ���� Ű �����⿡�� ������ Ű�ָ��� ���θ� Ǯ�ų� ���� �� �ִ�.
		// ������ ���� �� Ű�� �׻� ���� ���� ������ ���� �ƴ϶�� ���̴�.
		struct generate_key
		{
			/*! \brief ������
			*
			*	\param bytes Ű�� ũ��
			*	\remark Ű�� ũ��� 0�� �� ����.
			*	\exception UNKNOWN_ERROR openssl���� ������ ������, �����Ҹ�
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

			/*! \brief ����Ű ����
			*
			*	\remark Ű �����⿡�� ����Ű�� ��������.
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

				// ��� �ٸ� ���̳ʸ� ���� �����Ѵ�.
				// ������, �� Ű�� ���� �����⿡�� public Ű�� ��ȣȭ�� ���� ��ȣȭ�� �� �ִ�.
				// Ű�� ���̳ʸ� �迭�̴�.
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

			/*! \brief ����Ű ����
			*
			*	\remark Ű �����⿡�� ����Ű�� ��������.
			*/
			rsa_impl::public_key_type public_key()
			{
				const std::size_t PUBMODULUS = _key_bytes;
				const std::size_t PUBEXPONENT = 3;

				rsa_impl::public_key_type key;
				key.resize(PUBMODULUS + PUBEXPONENT);

				// ��� �ٸ� ���̳ʸ� ���� �����Ѵ�.
				// ������, �� Ű�� ��ȣȭ�ϸ� ���� �����⿡�� private Ű�� ��ȣȭ�� �� �ִ�.
				// Ű�� ���̳ʸ� �迭�̴�.
				std::size_t pos = 0;
				BN_bn2bin(_sch->n, &key[pos]);		pos += PUBMODULUS;
				BN_bn2bin(_sch->e, &key[pos]);		pos += PUBEXPONENT;

				return key;
			}

		private:
			//Ű�� �����ϰ� �����Ƿ�, �����ؼ��� �� �ȴ�. ���� ������ ��.
			generate_key(const generate_key &rhs);
			generate_key operator = (const generate_key &rhs);

			RSA				*_sch;
			std::size_t		_key_bytes;
		};		
	}
}

#endif //__RSA_HPP