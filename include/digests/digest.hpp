#ifndef __DIGEST_HPP
#define __DIGEST_HPP

namespace salm {

	namespace encode {
		
		// �⺻ ��ȣȭ��� ����
		// digest ��ȣȭ �˰����� ������ ���¸� ������.
		template <typename CTX_IN, typename Algorithm, std::size_t BC>
		struct DigestBASE
		{
			typedef typename Algorithm::message_input_type	input_type;
			typedef typename Algorithm::message_output_type	output_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			enum {
				BLOCK_COUNT = BC,		//BC�� �ؽ��� ũ��� bytes��(bytes * 8 = bits�� ����� bit���� ������)
			};
		
			DigestBASE() 
				: _ctx(), _impl()
			{}

			virtual ~DigestBASE()
			{}			

			/*! \brief �ʱ�ȭ
			*
			*	\retval >= 0 ���� ����, �׻� success =.=
			*/
			int initialize()
			{
				int ret = _impl.init(_ctx);
				return 0;
			}

			/*! \brief ��ȣȭ
			*
			*	\param src ��ȣȭ�ϰ��� �ϴ� ����
			*	\retval output_type ��ȣȭ�� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				// �� ��ü�� ���� ����� ���� �ִµ�, �ʱ�ȭ���� �ʴ� ���� �����Ѵ�.
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