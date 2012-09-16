//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/The_Seeds
#ifndef __SEED_HPP
#define __SEED_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "openssl/seed.h"
}

namespace salm {

	namespace seed {
		
		const std::size_t SEED_ENCRYPT = 1;
		const std::size_t SEED_DECRYPT = 0;
		// seed ecb 구현부
		struct ecb128
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);				
			}
			void init_decrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);
			}
			void encrypt(SEED_KEY_SCHEDULE &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 16)
				{
					SEED_ecb_encrypt(&src[0] + i, &dst[0] + i, &ctx, SEED_ENCRYPT);
				}
			}
			void decrypt(SEED_KEY_SCHEDULE &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 16)
				{
					SEED_ecb_encrypt(&src[0] + i, &dst[0] + i, &ctx, SEED_DECRYPT);
				}
			}
		};		

		// seed cbc 구현부
		struct cbc128
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);				
			}
			void init_decrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);
			}
			void encrypt(SEED_KEY_SCHEDULE &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				SEED_cbc_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], SEED_ENCRYPT);
			}
			void decrypt(SEED_KEY_SCHEDULE &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				SEED_cbc_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], SEED_DECRYPT);
			}
		};

		// seed cfb 구현부
		struct cfb128
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);			
			}
			void init_decrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);
			}
			void encrypt(SEED_KEY_SCHEDULE &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요 
				int bits = 1;
				// 패딩이 없어도 된다.
				SEED_cfb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits, SEED_ENCRYPT);
			}
			void decrypt(SEED_KEY_SCHEDULE &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요 
				int bits = 1;
				// 패딩이 없어도 된다.
				SEED_cfb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits, SEED_DECRYPT);
			}
		};		

		// seed ofb 구현부
		struct ofb128
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);
			}
			void init_decrypt(SEED_KEY_SCHEDULE &ctx, const key_type &key, const iv_type &iv)
			{
				SEED_set_key(&key[0], &ctx);
			}
			void encrypt(SEED_KEY_SCHEDULE &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				SEED_ofb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits);
			}
			void decrypt(SEED_KEY_SCHEDULE &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				SEED_ofb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits);
			}
		};
	}
}

#endif //__SEED_HPP