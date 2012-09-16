#ifndef __TRANSFORM_HPP
#define __TRANSFORM_HPP

namespace salm {

	namespace encode {

		// �⺻ �����ͺ�ȯ ��� ����
		// �����ͺ�ȯ �˰����� ������ ���·� �����Ǿ�� �Ѵ�.
		template <typename Algorithm>
		struct TransformBASE
		{	
			typedef typename Algorithm::encode_input_type	input_type;
			typedef typename Algorithm::encode_output_type	output_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			TransformBASE()
				: _impl()
			{}

			virtual ~TransformBASE()
			{}
			
			virtual int initialize()
			{
				return 0;
			}

			/*! \brief ���ڵ�
			*		
			*	\param src ���ڵ��ϰ��� �ϴ� ����
			*	\retval output_type ���ڵ��� ���ڿ��� �����Ѵ�.(���� ��ü�� ���� ���ڿ��� �ƴ� ���� ����)
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					dst = _impl.encode(src);
				}				

				return dst;
			}		

		protected:

			Algorithm			_impl;			//�����ͺ�ȯ �˰��� ���� ��ü
		};
	}

	namespace decode {

		// �⺻ �����ͺ�ȯ ��� ����
		// �����ͺ�ȯ �˰����� ������ ���·� �����Ǿ�� �Ѵ�.
		template <typename Algorithm>
		struct TransformBASE
		{	
			typedef typename Algorithm::decode_output_type	output_type;
			typedef typename Algorithm::decode_input_type	input_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			TransformBASE()
				: _impl()
			{}

			virtual ~TransformBASE()
			{}

			virtual int initialize()
			{
				return 0;
			}		
		
			/*! \brief ���ڵ�
			*
			*	\param src ���ڵ��ϰ��� �ϴ� ����
			*	\retval output_type ���ڵ��� ���̳ʸ� �迭�� �����Ѵ�.(���� ��ü�� ���� ���̳ʸ� �迭�� �ƴ� ���� ����)
			*/
			output_type execute(const input_type &src)
			{
				output_type dst;
				if (!src.empty())
				{
					dst = _impl.decode(src);
				}				

				return dst;
			}

		protected:

			Algorithm			_impl;			//�����ͺ�ȯ �˰��� ���� ��ü
		};
	}
}

#endif //__TRANSFORM_HPP