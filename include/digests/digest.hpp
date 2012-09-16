#ifndef __DIGEST_HPP
#define __DIGEST_HPP

namespace salm {

	namespace encode {
		
		// 기본 암호화모듈 형태
		// digest 암호화 알고리즘은 다음의 형태를 따른다.
		template <typename CTX_IN, typename Algorithm, std::size_t BC>
		struct DigestBASE
		{
			typedef typename Algorithm::message_input_type	input_type;
			typedef typename Algorithm::message_output_type	output_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			enum {
				BLOCK_COUNT = BC,		//BC는 해쉬값 크기로 bytes값(bytes * 8 = bits로 모듈의 bit수를 결정함)
			};
		
			DigestBASE() 
				: _ctx(), _impl()
			{}

			virtual ~DigestBASE()
			{}			

			/*! \brief 초기화
			*
			*	\retval >= 0 에러 여부, 항상 success =.=
			*/
			int initialize()
			{
				int ret = _impl.init(_ctx);
				return 0;
			}

			/*! \brief 암호화
			*
			*	\param src 암호화하고자 하는 내용
			*	\retval output_type 암호화된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				// 이 객체를 직접 사용할 수도 있는데, 초기화하지 않는 것을 방지한다.
				CTX_IN comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_ctx, &comp, sizeof(_ctx)), "module is not initialized");

				output_type dst;
				if (!src.empty())
				{
					int ret = _impl.update(_ctx, src);

					dst.resize(BLOCK_COUNT);
					ret = _impl.final(dst, _ctx);
				}

				return dst;
			}

		protected:

			CTX_IN				_ctx;
			Algorithm			_impl;
		};	
	}
}

#endif //__DIGEST_HPP