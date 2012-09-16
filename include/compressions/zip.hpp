//�߰�����
//- gzip ���� ���̺귯��(deflate �˰��� ����)
//- ��Ʈ������� �������� �ʴ´�.
//
//���۷���
//- wikipedia : http://en.wikipedia.org/wiki/ZLIB
//- zlib : http://www.zlib.net/manual.html
#ifndef __ZIP_HPP
#define __ZIP_HPP

#include "salm.hpp"
#include "compression.hpp"

extern "C" {
#include "zlib/zlib.h"
}

namespace salm {
	
	// zip ������ ������
	struct zip_impl
	{

		typedef byte_array				compress_input_type;
		typedef byte_array				compress_output_type;

		typedef byte_array				uncompress_input_type;
		typedef byte_array				uncompress_output_type;

		typedef EMPTY					key_type;
		typedef EMPTY					iv_type;
		
		uint64_t compressBound(const compress_input_type &src)
		{
			//ziblib�� ������ ũ�⸦ ���������� �ʴ´�. �����Ϳ� �־� ���۸� Ȯ���Ѵ�.
			return ::compressBound(src.size()) + sizeof(uint64_t);
		}

		uint64_t uncompressBound(const compress_input_type &src)
		{
			uint64_t length = 0;

			//byte order ó��(��Ʋ ����� ���� �ý��ۿ� �°� �д´�.)
			if (salm::is_big_endian()) length = _byteswap_uint64(*(reinterpret_cast<const uint64_t*>(&src[src.size() - sizeof(uint64_t)])));
			else length = *(reinterpret_cast<const uint64_t*>(&src[src.size() - sizeof(uint64_t)]));
			return length;
		}

		void compress(compress_output_type &dst, const compress_input_type &src)
		{
			uint64_t length = dst.size();
			int ok = ::compress(&dst[0], (uLongf *)&length, &src[0], src.size());
			if(Z_OK != ok) throw salm::exception("zip library error", salm::UNKNOWN_ERROR);
						
			dst.resize(length + sizeof(uint64_t));

			//byte order ó��(��Ʋ ��������� �����Ѵ�.)
			if (salm::is_big_endian()) *(reinterpret_cast<uint64_t*>(&dst[length])) = _byteswap_uint64(static_cast<uint64_t>(src.size()));
			else *(reinterpret_cast<uint64_t*>(&dst[length])) = static_cast<uint64_t>(src.size());
		}

		void uncompress(uncompress_output_type &dst, const uncompress_input_type &src)
		{
			uint64_t length = dst.size();

			int ok = ::uncompress(&dst[0], (uLongf *)&length, &src[0], src.size());
			if(Z_OK != ok) throw salm::exception("zip library error", salm::UNKNOWN_ERROR);

			dst.resize(length);
		}
	};	
}

#endif //__ZIP_HPP