//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/Rabbit_(cipher)
#ifndef __RABBIT_HPP
#define __RABBIT_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "eSTREAM_Project/ecrypt-rabbit.h"
}

namespace salm {

	namespace rabbit {
		// rabbit 구현부		
		struct rabbit128
		{
			typedef byte_array					encrypt_input_type;
			typedef byte_array					encrypt_output_type;
			typedef encrypt_output_type			decrypt_input_type;
			typedef encrypt_input_type			decrypt_output_type;

			typedef byte_array					key_type;
			typedef byte_array					iv_type;

			void init_encrypt(RABBIT_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				RABBIT_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				RABBIT_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void init_decrypt(RABBIT_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				RABBIT_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				RABBIT_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void encrypt(RABBIT_ECRYPT_ctx &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				RABBIT_ECRYPT_encrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
			void decrypt(RABBIT_ECRYPT_ctx &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				RABBIT_ECRYPT_decrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
		};
	}
}

#endif //__RABBIT_HPP