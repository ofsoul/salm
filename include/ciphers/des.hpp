//레퍼런스
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
		// des ecb 구현부
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
				// 8 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);
				
				for (int i = 0; i < src.size(); i += 8)
				{
					DES_ecb_encrypt((const_DES_cblock *)(&src[0] + i), (DES_cblock *)(&dst[0] + i), &ctx, DES_ENCRYPT);
				}
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 8 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 8)
				{
					DES_ecb_encrypt((const_DES_cblock *)(&src[0] + i), (DES_cblock *)(&dst[0] + i), &ctx, DES_DECRYPT);
				}
			}
		};

		// des cbc 구현부
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
				// 8 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				DES_ncbc_encrypt(&src[0], &dst[0], src.size(), &ctx, (DES_cblock*)&iv[0], DES_ENCRYPT);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 8 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 8) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				DES_ncbc_encrypt(&src[0], &dst[0], src.size(), &ctx, (DES_cblock*)&iv[0], DES_DECRYPT);
			}
		};

		// des cfb 구현부
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
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 1;
				// 패딩이 없어도 된다.
				DES_cfb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0], DES_ENCRYPT);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 1;
				// 패딩이 없어도 된다.
				DES_cfb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0], DES_DECRYPT);
			}
		};

		// des ofb 구현부
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
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				DES_ofb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0]);
			}
			void decrypt(DES_key_schedule &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				DES_ofb_encrypt(&src[0], &dst[0], bits, src.size(), &ctx, (DES_cblock*)&iv[0]);
			}
		};
	}
}

#endif //__DES_HPP