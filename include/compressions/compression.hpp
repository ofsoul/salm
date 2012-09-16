#ifndef __COMPRESSION_HPP
#define __COMPRESSION_HPP

//std::uint64_t 4G�̻��� �����ϱ� ����
#ifdef _MSC_VER
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

namespace salm {
	
	namespace encode {

		// �⺻ ������ ����
		// ���� �˰����� ������ ���·� �����Ǿ�� �Ѵ�.
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

			/*! \brief ����
			*
			*	\param src �����ϰ��� �ϴ� ����
			*	\retval output_type ����� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					//Ȯ���ؾ� �ϴ� ũ��
					//�������� ���� ���� ������ ����ũ�⸦ �����ؾ� �Ѵ�.
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
		
			Algorithm			_impl;			//���� �˰��� ���� ��ü
		};
	}

	namespace decode {
		// �⺻ ������� ����
		// ���� �˰����� ������ ���·� �����Ǿ�� �Ѵ�.
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

			/*! \brief ����
			*
			*	\param src �����ϰ��� �ϴ� ����
			*	\retval output_type ������ �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					//Ȯ���ؾ� �ϴ� ũ��
					//��������� ���� ���� ������ ����ũ�⸦ �����ؾ� �Ѵ�.
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
		
			Algorithm			_impl;			//���� �˰��� ���� ��ü
		};
	}
}

#endif //__COMPRESSION_HPP