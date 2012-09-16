//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
#ifndef __AES_HPP
#define __AES_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "openssl/aes.h"
}

namespace salm {

	namespace aes {			
		// aes ecb 구현부
		struct ecb
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void init_decrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_decrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void encrypt(AES_KEY &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 16)
				{
					AES_ecb_encrypt((&src[0] + i), (&dst[0] + i), (const AES_KEY*)&ctx, AES_ENCRYPT);
				}
			}
			void decrypt(AES_KEY &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				for (int i = 0; i < src.size(); i += 16)
				{
					AES_ecb_encrypt((&src[0] + i), (&dst[0] + i), (const AES_KEY*)&ctx, AES_DECRYPT);
				}
			}
		};		

		// aes cbc 구현부
		struct cbc
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void init_decrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_decrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void encrypt(AES_KEY &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				AES_cbc_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], AES_ENCRYPT);
			}
			void decrypt(AES_KEY &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 16 블록(bytes)의 배수가 아닐경우 예외, 패딩을 사용할 것.
				if (0 != src.size() % 16) throw salm::exception("block size should be a fixed multiple", salm::INVALID_BAD_MULTIPLE);

				AES_cbc_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], AES_DECRYPT);
			}
		};

		// aes cfb 구현부
		struct cfb
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void init_decrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				// 같은 키 초기화함수를 통해 복호화해야 한다.
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void encrypt(AES_KEY &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 1;
				// 패딩이 없어도 된다.
				AES_cfb8_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits, AES_ENCRYPT);
			}
			void decrypt(AES_KEY &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 1;
				// 패딩이 없어도 된다.
				AES_cfb8_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits, AES_DECRYPT);
			}
		};			

		// aes ofb 구현부
		struct ofb
		{
			typedef byte_array			encrypt_input_type;
			typedef byte_array			encrypt_output_type;
			typedef byte_array			decrypt_input_type;
			typedef byte_array			decrypt_output_type;

			typedef byte_array			key_type;
			typedef byte_array			iv_type;

			void init_encrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void init_decrypt(AES_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				// 같은 키 초기화함수를 통해 복호화해야 한다.
				AES_set_encrypt_key(&key[0], key.size() * 8, &ctx);
			}
			void encrypt(AES_KEY &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				AES_ofb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits);
			}
			void decrypt(AES_KEY &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				// 아직 bits값에 대한 것은 모호함. 조사 필요
				int bits = 8;
				// 패딩이 없어도 된다.
				AES_ofb128_encrypt(&src[0], &dst[0], src.size(), &ctx, &iv[0], &bits);
			}
		};
	}	
}

#endif //__AES_HPP