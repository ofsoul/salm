//���۷���
//- openssl : http://www.openssl.org/docs/crypto/des.html#
//- wikipedia : http://en.wikipedia.org/wiki/Data_Encryption_Standard
#ifndef __DES_HPP
#define __DES_HPP

#include "cipher.hpp"

extern "C" {
#include "openssl/des.h"
}

namespace salm {

	namespace des {		
		// des ecb ������
		struct ecb64
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);				
			}
			void init_decrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);
			}
			void encrypt(DES_key_schedule &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 8 ���(bytes)�� ����� �ƴҰ�� ����, �е��� ����� ��.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);
				
				for (int i = 0; i < src.size(); i += 8)
				{
					DES_ecb_encrypt((const_DES_cblock *)(&src[0] + i), (DES_cblock *)(&dst[0] + i), &ctx, DES_ENCRYPT);
				}
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 8 ���(bytes)�� ����� �ƴҰ�� ����, �е��� ����� ��.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 8)
				{
					DES_ecb_encrypt((const_DES_cblock *)(&src[0] + i), (DES_cblock *)(&dst[0] + i), &ctx, DES_DECRYPT);
				}
			}
		};

		// des cbc ������
		struct cbc64
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);				
			}
			void init_decrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);
			}
			void encrypt(DES_key_schedule &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 8 ���(bytes)�� ����� �ƴҰ�� ����, �е��� ����� ��.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				DES_ncbc_encrypt(&src[0], &dst[0], src.size(), &ctx, (DES_cblock*)&iv[0], DES_ENCRYPT);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 8 ���(bytes)�� ����� �ƴҰ�� ����, �е��� ����� ��.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				DES_ncbc_encrypt(&src[0], &dst[0], src.size(), &ctx, (DES_cblock*)&iv[0], DES_DECRYPT);
			}
		};

		// des cfb ������
		struct cfb64
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);				
			}
			void init_decrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);
			}
			void encrypt(DES_key_schedule &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// ���� bits���� ���� ���� ��ȣ��. ���� �ʿ�
				int bits = 1;
				// �е��� ��� �ȴ�.
				DES_cfb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0], DES_ENCRYPT);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// ���� bits���� ���� ���� ��ȣ��. ���� �ʿ�
				int bits = 1;
				// �е��� ��� �ȴ�.
				DES_cfb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0], DES_DECRYPT);
			}
		};

		// des ofb ������
		struct ofb64
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);				
			}
			void init_decrypt(DES_key_schedule &ctx, const key_type &key, const iv_type &iv)
			{
				DES_set_key_unchecked((const_DES_cblock *)&key[0], &ctx);
			}
			void encrypt(DES_key_schedule &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// ���� bits���� ���� ���� ��ȣ��. ���� �ʿ�
				int bits = 8;
				// �е��� ��� �ȴ�.
				DES_ofb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0]);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// ���� bits���� ���� ���� ��ȣ��. ���� �ʿ�
				int bits = 8;
				// �е��� ��� �ȴ�.
				DES_ofb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0]);
			}
		};
	}
}

#endif //__DES_HPP