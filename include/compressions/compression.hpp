#ifndef __COMPRESSION_HPP
#define __COMPRESSION_HPP

//std::uint64_t 4G이상을 지원하기 위함
#ifdef _MSC_VER
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

namespace salm {
	
	namespace encode {

		// 기본 압축모듈 형태
		// 압축 알고리즘은 다음의 형태로 구현되어야 한다.
		template <typename Algorithm>
		struct CompressionBASE
		{
			typedef typename Algorithm::compress_input_type		input_type;
			typedef typename Algorithm::compress_output_type	output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			CompressionBASE()
				: _impl()
			{}

			virtual ~CompressionBASE()
			{}

			virtual int initialize()
			{
				return 0;
			}

			/*! \brief 압축
			*
			*	\param src 압축하고자 하는 내용
			*	\retval output_type 압축된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					//확보해야 하는 크기
					//압축모듈은 필히 예측 가능한 압축크기를 리턴해야 한다.
					uint64_t length = _impl.compressBound(src);

					if (length > 0)
					{
						dst.resize(length);

						_impl.compress(dst, src);					
					}				
				}				

				return dst;
			}

		protected:
		
			Algorithm			_impl;			//압축 알고리즘 구현 객체
		};
	}

	namespace decode {
		// 기본 복원모듈 형태
		// 복원 알고리즘은 다음의 형태로 구현되어야 한다.
		template <typename Algorithm>
		struct CompressionBASE
		{
			typedef typename Algorithm::uncompress_input_type	input_type;
			typedef typename Algorithm::uncompress_output_type	output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;


			CompressionBASE()
				: _impl()
			{}

			virtual ~CompressionBASE()
			{}

			virtual int initialize()
			{
				return 0;
			}

			/*! \brief 복원
			*
			*	\param src 복원하고자 하는 내용
			*	\retval output_type 복원된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					//확보해야 하는 크기
					//복원모듈은 필히 예측 가능한 복원크기를 리턴해야 한다.
					uint64_t length = _impl.uncompressBound(src);

					if (length > 0)
					{
						dst.resize(length);

						_impl.uncompress(dst, src);
					}				
				}

				return dst;
			}

		protected:
		
			Algorithm			_impl;			//복원 알고리즘 구현 객체
		};
	}
}

#endif //__COMPRESSION_HPP