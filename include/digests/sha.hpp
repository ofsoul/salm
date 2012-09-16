//레퍼런스
//- openssl : http://www.openssl.org/docs/crypto/sha.html#
//- wikipedia : http://en.wikipedia.org/wiki/SHA_hash_functions
#ifndef __SHA_HPP
#define __SHA_HPP

#include "salm.hpp"
#include "digest.hpp"

extern "C" {
#include "openssl/sha.h"
}

namespace salm {	

	namespace sha {

		// sha 160비트 구현부
		struct sha160
		{
			typedef byte_array			message_input_type;
			typedef byte_array			message_output_type;

			typedef EMPTY				key_type;					
			typedef EMPTY				iv_type;

			int init(SHA_CTX &ctx)
			{
				return SHA1_Init(&ctx);
			}
			int update(SHA_CTX &ctx, const message_input_type &src)
			{
				return SHA1_Update(&ctx, &src[0], src.size());
			}
			int final(message_output_type &dst, SHA_CTX &ctx)
			{
				return SHA1_Final(&dst[0], &ctx);
			}
		};		

		// sha 256비트 구현부
		struct sha256
		{
			typedef byte_array			message_input_type;
			typedef byte_array			message_output_type;

			typedef EMPTY				key_type;					
			typedef EMPTY				iv_type;

			int init(SHA256_CTX &ctx)
			{
				return SHA256_Init(&ctx);
			}
			int update(SHA256_CTX &ctx, const message_input_type &src)
			{
				return SHA256_Update(&ctx, &src[0], src.size());
			}
			int final(message_output_type &dst, SHA256_CTX &ctx)
			{
				return SHA256_Final(&dst[0], &ctx);
			}
		};

		// sha 512비트 구현부
		struct sha512
		{
			typedef byte_array			message_input_type;
			typedef byte_array			message_output_type;

			typedef EMPTY				key_type;					
			typedef EMPTY				iv_type;

			int init(SHA512_CTX &ctx)
			{
				return SHA512_Init(&ctx);
			}
			int update(SHA512_CTX &ctx, const message_input_type &src)
			{
				return SHA512_Update(&ctx, &src[0], src.size());
			}
			int final(message_output_type &dst, SHA512_CTX &ctx)
			{
				return SHA512_Final(&dst[0], &ctx);
			}
		};
	}
}

#endif //__SHA_HPP