#ifndef __INTERFACE_HPP
#define __INTERFACE_HPP

#include <cstddef>		//visual studio 2008(vc9) 지원을 위함

namespace salm {

	// brief 사용자 인터페이스 
	template <typename MODULE>
	struct crypto
	{
		typedef typename MODULE::input_type				input_type;
		typedef typename MODULE::output_type			output_type;

		typedef typename MODULE::key_type				key_type;
		typedef typename MODULE::iv_type				iv_type;

		typedef typename input_type::const_pointer		const_input_pointer;
		typedef typename key_type::const_pointer		const_key_pointer;
		typedef typename iv_type::const_pointer			const_iv_pointer;

		crypto()
		{			
			int ret = _module.initialize();
		}

		crypto(const_key_pointer hint, std::size_t hint_len)
		{
			int ret = _module.initialize(key_type(hint, reinterpret_cast<const_key_pointer>((byte*)hint + hint_len)));
		}

		crypto(const key_type &hint)
		{
			int ret = _module.initialize(hint);
		}

		crypto(const_key_pointer hint, std::size_t hint_len, iv_type &iv)
		{
			int ret = _module.initialize(key_type(hint, reinterpret_cast<const_key_pointer>((byte*)hint + hint_len)), iv);
		}

		crypto(key_type &hint, const_iv_pointer iv, std::size_t iv_len)
		{
			int ret = _module.initialize(hint, iv_type(iv, reinterpret_cast<const_iv_pointer>((byte*)iv + iv_len)));
		}

		crypto(const_key_pointer hint, std::size_t hint_len, const_iv_pointer iv, std::size_t iv_len)
		{
			int ret = _module.initialize(key_type(hint, reinterpret_cast<const_key_pointer>((byte*)hint + hint_len)), 
				iv_type(iv, reinterpret_cast<const_iv_pointer>((byte*)iv + iv_len)));
		}

		crypto(const key_type &hint, const iv_type &iv)
		{
			int ret = _module.initialize(hint, iv);
		}

		~crypto()
		{}

		inline output_type execute(const_input_pointer src, std::size_t src_len) {
			return this->execute(input_type(src, src + src_len));
		}

		inline output_type execute(const input_type &src) {
			return _module.execute(src);
		}

		MODULE				_module;				// 암호화 모듈		
	};
}

#endif //__INTERFACE_HPP