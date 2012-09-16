//레퍼런스
//- wikipedia : http://www.openssl.org/docs/crypto/rc4.html#
#ifndef __RC4_HPP
#define __RC4_HPP

#include "salm.hpp"
#include "cipher.hpp"

extern "C" {
#include "openssl/rc4.h"
}

namespace salm {

	namespace rc4 {		
		// rc4 구현부
		struct rc4_128
		{
			typedef byte_array					encrypt_input_type;
			typedef byte_array					encrypt_output_type;
			typedef encrypt_output_type			decrypt_input_type;
			typedef encrypt_input_type			decrypt_output_type;

			typedef byte_array					key_type;
			typedef byte_array					iv_type;

			void init_encrypt(RC4_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				RC4_set_key(&ctx, key.size(), &key[0]);
			}
			void init_decrypt(RC4_KEY &ctx, const key_type &key, const iv_type &iv)
			{
				RC4_set_key(&ctx, key.size(), &key[0]);
			}
			void encrypt(RC4_KEY &ctx, encrypt_output_type &dst, const encrypt_input_type &src, iv_type &iv)
			{
				RC4(&ctx, src.size(), &src[0], &dst[0]);
			}
			void decrypt(RC4_KEY &ctx, decrypt_output_type &dst, const decrypt_input_type &src, iv_type &iv)
			{
				RC4(&ctx, src.size(), &src[0], &dst[0]);
			}
		};
	}
}

#endif //__RC4_HPP