#ifndef __TRANSFORM_HPP
#define __TRANSFORM_HPP

namespace salm {

	namespace encode {

		// 기본 데이터변환 모듈 형태
		// 데이터변환 알고리즘은 다음의 형태로 구현되어야 한다.
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

			/*! \brief 인코딩
			*		
			*	\param src 인코딩하고자 하는 내용
			*	\retval output_type 인코딩된 문자열을 리턴한다.(구현 객체에 따라 문자열이 아닐 수도 있음)
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

			Algorithm			_impl;			//데이터변환 알고리즘 구현 객체
		};
	}

	namespace decode {

		// 기본 데이터변환 모듈 형태
		// 데이터변환 알고리즘은 다음의 형태로 구현되어야 한다.
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
		
			/*! \brief 디코딩
			*
			*	\param src 디코딩하고자 하는 내용
			*	\retval output_type 디코딩된 바이너리 배열을 리턴한다.(구현 객체에 따라 바이너리 배열이 아닐 수도 있음)
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

			Algorithm			_impl;			//데이터변환 알고리즘 구현 객체
		};
	}
}

#endif //__TRANSFORM_HPP