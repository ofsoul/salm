#ifndef __PADDING_HPP
#define __PADDING_HPP

#include "salm.hpp"			//byte_array
#include <ctime>			//std::time
#include <algorithm>		//std::generate, std::srand

namespace salm {
	namespace padding {

		struct NONE
		{			
			template <std::size_t blockcount>
			void add(byte_array &src)
			{

			}

			template <std::size_t blockcount>
			void remove(byte_array &src)
			{

			}
		};

		struct PKCS7
		{
			template <std::size_t blockcount>
			void add(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );	

				std::size_t block = blockcount - (src.size() % blockcount);
				src.resize(src.size() + block, block);
			}

			template <std::size_t blockcount>
			void remove(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				// pkcs7을 사용한 경우라면, 반드시 패딩이 있다고 가정한다.
				if (src.empty()) throw salm::exception("There is no source data", INVALID_NO_DATA);

				// pkcs7인지 패딩 전체를 검사하는게 맞지만, 중요하지 것은 아니므로 패스
				byte block = *src.rbegin();
				if (block > blockcount) throw salm::exception("block size should be a fixed multiple", INVALID_BAD_MULTIPLE);
				if (block > src.size()) throw salm::exception("block size is larger than the data", INVALID_BAD_PADDING_BYTES);

				src.resize(src.size() - block);
			}
		};

		struct Zeros
		{
			template <std::size_t blockcount>
			void add(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				std::size_t block = (blockcount - (src.size() % blockcount)) % blockcount;
				src.resize(src.size() + block);
			}

			template <std::size_t blockcount>
			void remove(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				std::size_t block = (blockcount - (src.size() % blockcount)) % blockcount;
				if (block > src.size()) throw salm::exception("block size is larger than the data", INVALID_BAD_PADDING_BYTES);

				// Zeros 패딩은 안 붙을 수도 있기때문에 원본 데이터에 0의 갯수를 알 수 없다.
				//   - 원본 데이터 끝부분에 0이 있을 경우 패딩인지 데이터의 0인지 알 수 없음
				// 패딩을 제거할 수 없다. 사용자에게 맡긴다.				
				//src.resize(src.size() - block);
			}
		};

		struct ANSIX923
		{
			template <std::size_t blockcount>
			void add(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				std::size_t block = blockcount - (src.size() % blockcount);
				src.resize(src.size() + block);
				*src.rbegin() = block;
			}

			template <std::size_t blockcount>
			void remove(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				// ANSIX923을 사용한 경우라면, 반드시 패딩이 있다고 가정한다.
				if (src.empty()) throw salm::exception("There is no source data", INVALID_NO_DATA);
				byte block = *src.rbegin();

				if (block > blockcount) throw salm::exception("block size should be a fixed multiple", INVALID_BAD_MULTIPLE);
				if (block > src.size()) throw salm::exception("block size is larger than the data", INVALID_BAD_PADDING_BYTES);				
				src.resize(src.size() - block);
			}
		};		

		byte random_bytes()
		{
			return rand() % 256;
		}

		struct ISO10126
		{
			template <std::size_t blockcount>
			void add(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				std::size_t length = src.size();
				std::size_t block = blockcount - (src.size() % blockcount);
				src.resize(length + block);

				std::srand(std::time(0));
				//std::generate(src.begin() + length, src.end() - 1, []()->byte { 
				//	return rand() % 256; 
				//});
				std::generate(src.begin() + length, src.end() - 1, random_bytes);
				*src.rbegin() = block;
			}

			template <std::size_t blockcount>
			void remove(byte_array &src)
			{
				salm_static_assert( 0 != blockcount, "block size is not zero" );

				// ISO10126을 사용한 경우라면, 반드시 패딩이 있다고 가정한다.
				if (src.empty()) throw salm::exception("There is no source data", INVALID_NO_DATA);

				// 패딩 전체를 검사하여 ISO10126인지 / ANSIX923인지 확인해야겠지만, 중요하지 것은 아니므로 패스
				byte block = *src.rbegin();

				if (block > blockcount) throw salm::exception("block size should be a fixed multiple", INVALID_BAD_MULTIPLE);
				if (block > src.size()) throw salm::exception("block size is larger than the data", INVALID_BAD_PADDING_BYTES);
				src.resize(src.size() - block);
			}
		};
	}
}

#endif //__PADDING_HPP