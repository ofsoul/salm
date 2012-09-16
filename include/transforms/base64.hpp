#ifndef __BASE64_HPP
#define __BASE64_HPP

#include "salm.hpp"
#include "transform.hpp"

namespace salm {
	
	// 다음의 코드를 사용했다. https://github.com/ReneNyffenegger/development_misc/tree/master/base64
	// salm 인터페이스 및 사용형식에 맞게 수정했다.
	// base64 실제 구현부
	struct base64_impl
	{
		typedef byte_array				encode_input_type;
		typedef std::string				encode_output_type;

		typedef byte_array				decode_output_type;
		typedef std::string				decode_input_type;

		typedef EMPTY					key_type;					
		typedef EMPTY					iv_type;

		base64_impl() : base64_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
		{}

		encode_output_type encode(const encode_input_type &src)	
		{
			encode_output_type ret;
			int i = 0;
			int j = 0;
			byte char_array_3[3];
			byte char_array_4[4];

			for (encode_input_type::const_iterator iter = src.begin(); iter != src.end(); iter++)
			{
				char_array_3[i++] = *(iter);
				if (i == 3) {
					char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
					char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
					char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
					char_array_4[3] = char_array_3[2] & 0x3f;

					for(i = 0; (i <4) ; i++)
						ret += base64_chars[char_array_4[i]];
					i = 0;
				}
			}

			if (i)
			{
				for(j = i; j < 3; j++)
					char_array_3[j] = '\0';

				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (j = 0; (j < i + 1); j++)
					ret += base64_chars[char_array_4[j]];

				while((i++ < 3))
					ret += '=';

			}

			return ret;
		}

		bool is_base64(char c)
		{
			return (isalnum(c) || (c == '+') || (c == '/')); 
		}

		decode_output_type decode(const decode_input_type &src) 
		{		
			int i = 0;
			int j = 0;
			int in_ = 0;
			byte char_array_4[4], char_array_3[3];		
			decode_input_type ret;

			int in_len = src.size();
			while (in_len-- && ( src[in_] != '=') && is_base64(src[in_])) 
			{
				char_array_4[i++] = src[in_]; in_++;
				if (i ==4) {
					for (i = 0; i <4; i++)
						char_array_4[i] = base64_chars.find(char_array_4[i]);

					char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
					char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
					char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

					for (i = 0; (i < 3); i++)
						ret += char_array_3[i];
					i = 0;
				}
			}

			if (i) {
				for (j = i; j <4; j++)
					char_array_4[j] = 0;

				for (j = 0; j <4; j++)
					char_array_4[j] = base64_chars.find(char_array_4[j]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
			}

			return salm::string_to_bytes(ret);
		}

	private:
		const std::string base64_chars;
	};
}

#endif //__BASE64_HPP