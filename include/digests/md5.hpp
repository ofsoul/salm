//레퍼런스
//- openssl : http://www.openssl.org/docs/crypto/md5.html#
//- wikipedia : http://en.wikipedia.org/wiki/MD5
#ifndef __MD5_HPP
#define __MD5_HPP

#include "salm.hpp"
#include "digest.hpp"

extern "C" {
#include "openssl/md5.h"
}

namespace salm {
	
	namespace md5 {

		// md5 구현부
		struct md5_impl
		{
			typedef byte_array			message_input_type;
			typedef byte_array			message_output_type;

			typedef EMPTY				key_type;					
			typedef EMPTY				iv_type;

			int init(MD5_CTX &ctx)
			{
				return MD5_Init(&ctx);
			}
			int update(MD5_CTX &ctx, const message_input_type &src)
			{
				return MD5_Update(&ctx, &src[0], src.size());
			}
			int final(message_output_type &dst, MD5_CTX &ctx)
			{
				return MD5_Final(&dst[0], &ctx);
			}
		};
	}	
}

#endif //__MD5_HPP