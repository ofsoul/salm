//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/SOSEMANUK
#ifndef __SOSEMANUK_HPP
#define __SOSEMANUK_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "eSTREAM_Project/ecrypt-sosemanuk.h"
}

namespace salm {	

	namespace sosemanuk {

		// sosemanuk 구현부
		struct sosemanuk256
		{
			typedef byte_array					encrypt_input_type;
			typedef byte_array					encrypt_output_type;
			typedef encrypt_output_type			decrypt_input_type;
			typedef encrypt_input_type			decrypt_output_type;

			typedef byte_array					key_type;
			typedef byte_array					iv_type;

			void init_encrypt(SOSEMANUK_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				SOSEMANUK_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				SOSEMANUK_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void init_decrypt(SOSEMANUK_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				SOSEMANUK_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				SOSEMANUK_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void encrypt(SOSEMANUK_ECRYPT_ctx &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				SOSEMANUK_ECRYPT_encrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
			void decrypt(SOSEMANUK_ECRYPT_ctx &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				SOSEMANUK_ECRYPT_decrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
		};
	}
}

#endif //__SOSEMANUK_HPP