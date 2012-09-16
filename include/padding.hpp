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

				// pkcs7�� ����� �����, �ݵ�� �е��� �ִٰ� �����Ѵ�.
				if (src.empty()) throw salm::exception("There is no source data", INVALID_NO_DATA);

				// pkcs7���� �е� ��ü�� �˻��ϴ°� ������, �߿����� ���� �ƴϹǷ� �н�
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

				// Zeros �е��� �� ���� ���� �ֱ⶧���� ���� �����Ϳ� 0�� ������ �� �� ����.
				//   - ���� ������ ���κп� 0�� ���� ��� �е����� �������� 0���� �� �� ����
				// �е��� ������ �� ����. ����ڿ��� �ñ��.				
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

				// ANSIX923�� ����� �����, �ݵ�� �е��� �ִٰ� �����Ѵ�.
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

				// ISO10126�� ����� �����, �ݵ�� �е��� �ִٰ� �����Ѵ�.
				if (src.empty()) throw salm::exception("There is no source data", INVALID_NO_DATA);

				// �е� ��ü�� �˻��Ͽ� ISO10126���� / ANSIX923���� Ȯ���ؾ߰�����, �߿����� ���� �ƴϹǷ� �н�
				byte block = *src.rbegin();

				if (block > blockcount) throw salm::exception("block size should be a fixed multiple", INVALID_BAD_MULTIPLE);
				if (block > src.size()) throw salm::exception("block size is larger than the data", INVALID_BAD_PADDING_BYTES);
				src.resize(src.size() - block);
			}
		};
	}
}

#endif //__PADDING_HPP