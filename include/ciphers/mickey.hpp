//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/MICKEY-128
#ifndef __MICKEY_HPP
#define __MICKEY_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "eSTREAM_Project/ecrypt-mickey128.h"
}

namespace salm {

	namespace mickey {
		// mickey 구현부
		struct mickey128
		{
			typedef byte_array					encrypt_input_type;
			typedef byte_array					encrypt_output_type;
			typedef encrypt_output_type			decrypt_input_type;
			typedef encrypt_input_type			decrypt_output_type;

			typedef byte_array					key_type;
			typedef byte_array					iv_type;

			void init_encrypt(MICKEY128_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				MICKEY128_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				MICKEY128_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void init_decrypt(MICKEY128_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				MICKEY128_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				MICKEY128_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void encrypt(MICKEY128_ECRYPT_ctx &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				MICKEY128_ECRYPT_encrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
			void decrypt(MICKEY128_ECRYPT_ctx &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				MICKEY128_ECRYPT_decrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
		};
	}
}

#endif //__MICKEY_HPP