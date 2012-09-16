//레퍼런스
//- wikipedia : http://en.wikipedia.org/wiki/HC-128
#ifndef __HC_HPP
#define __HC_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "eSTREAM_Project/ecrypt-hc.h"
}

namespace salm {

	namespace hc {
		// hc 구현부	
		struct hc128
		{
			typedef byte_array					encrypt_input_type;
			typedef byte_array					encrypt_output_type;
			typedef encrypt_output_type			decrypt_input_type;
			typedef encrypt_input_type			decrypt_output_type;

			typedef byte_array					key_type;
			typedef byte_array					iv_type;

			void init_encrypt(HC128_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				HC128_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				HC128_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void init_decrypt(HC128_ECRYPT_ctx &ctx, const key_type &key, const iv_type &iv)
			{
				HC128_ECRYPT_keysetup(&ctx, &key[0], key.size() * 8, iv.size() * 8);
				HC128_ECRYPT_ivsetup(&ctx, &iv[0]);
			}
			void encrypt(HC128_ECRYPT_ctx &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				HC128_ECRYPT_encrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
			void decrypt(HC128_ECRYPT_ctx &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				HC128_ECRYPT_decrypt_bytes(&ctx, &src[0], &dst[0], src.size());
			}
		};
	}
}

#endif //__HC_HPP