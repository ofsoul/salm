#ifndef __CIPHER_HPP
#define __CIPHER_HPP

#include "padding.hpp"

namespace salm {

	namespace encode {

		// 기본 암호화모듈 형태
		// stream cipher 암호화 알고리즘은 다음의 형태를 따른다.
		template <typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV>
		struct StreamCipherBASE
		{
			typedef typename Algorithm::encrypt_input_type	input_type;
			typedef typename Algorithm::encrypt_output_type	output_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			enum 
			{
				KEY_BYTES = KB,			//KB는 키값 크기로 bytes값(bytes * 8 = bits로 모듈의 bit수를 결정함)
				IV_BYTES = IV,			//IV는 IV값 크기로 bytes값(bytes * 8 = bits)
			};

			StreamCipherBASE()
				: _en_sch(), _impl()
			{}

			virtual ~StreamCipherBASE()
			{}		
			
			int initialize()
			{
				// 이기종간 데이터를 주고 받을 경우, IV는 예측 가능해야 하며 변경도 가능해야 한다.
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
		
			int initialize(const key_type &key)
			{
				// 이기종간 데이터를 주고 받을 경우, IV는 예측 가능해야 하며 변경도 가능해야 한다.
				return init(key, salm::static_bytes(IV_BYTES));
			}

			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief 암호화
			*		
			*	\param src 암호화하고자 하는 내용
			*	\retval output_type 암호화된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				// 이 객체를 직접 사용할 수도 있는데, 초기화하지 않는 것을 방지한다.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_en_sch, &comp, sizeof(_en_sch)), "key is not initialized");

				output_type dst;
				if (!src.empty())
				{				
					dst.resize(src.size());

					_impl.encrypt(_en_sch, dst, src, _ivector);
				}			

				return dst;
			}		

			key_type			_userkey;			//!< 바이너리 키, 사용자가 복사하는 것을 허용한다.
			iv_type				_ivector;			//!< 바이너리 IV, 사용자가 복사하는 것을 허용한다.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// 키값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_encrypt(_en_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_en_sch;
			Algorithm			_impl;
		};

		// 기본 암호화모듈 형태
		// block cipher 암호화 알고리즘은 다음의 형태를 따른다.
		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV, std::size_t BC>
		struct BlockCipherBASE
		{
			typedef typename Algorithm::encrypt_input_type		input_type;
			typedef typename Algorithm::encrypt_output_type		output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,				//KB는 키값 크기로 bytes값(bytes * 8 = bits로 모듈의 bit수를 결정함)
				IV_BYTES = IV,				//IV는 IV값 크기로 bytes값(bytes * 8 = bits)
				BLOCK_COUNT = BC,			//BC는 블록 bytes의 크기로 byte 개수, 패딩 bytes 개수에 사용된다.
			};

			BlockCipherBASE()
				: _en_sch(), _impl()
			{}

			virtual ~BlockCipherBASE()
			{}					
			
			int initialize()
			{
				// 이기종간 데이터를 주고 받을 경우, IV는 예측 가능해야 하며 변경도 가능해야 한다.
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
					
			int initialize(const key_type &key)
			{			
				// 이기종간 데이터를 주고 받을 경우, IV는 예측 가능해야 하며 변경도 가능해야 한다.
				return init(key, salm::static_bytes(IV_BYTES));
			}

			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief 암호화
			*
			*	\param src 암호화하고자 하는 내용
			*	\retval output_type 암호화된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				// 이 객체를 직접 사용할 수도 있는데, 초기화하지 않는 것을 방지한다.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_en_sch, &comp, sizeof(_en_sch)), "key is not initialized");

				output_type dst;
				if (!src.empty())
				{
					// 사용자가 선택한 패딩 규칙이 적용된다.
					Padding padding;
					input_type copy_i = src;
					padding.add<BLOCK_COUNT>(copy_i);
					dst.resize(copy_i.size());

					_impl.encrypt(_en_sch, dst, copy_i, _ivector);				
				}		

				return dst;
			}

			key_type		_userkey;			//!< 바이너리 키, 사용자가 복사하는 것을 허용한다.
			iv_type			_ivector;			//!< 바이너리 IV	, 사용자가 복사하는 것을 허용한다.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// 키값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_encrypt(_en_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_en_sch;
			Algorithm			_impl;
		};
	}

	namespace decode {

		// 기본 복호화모듈 형태
		// stream cipher 복호화 알고리즘은 다음의 형태를 따른다.
		template <typename KEY_SCHEDULE, typename Algorithm,	std::size_t KB, std::size_t IV>
		struct StreamCipherBASE
		{
			typedef typename Algorithm::decrypt_input_type		input_type;
			typedef typename Algorithm::decrypt_output_type		output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,			//KB는 키값 크기로 bytes값(bytes * 8 = bits로 모듈의 bit수를 결정함)
				IV_BYTES = IV,			//IV는 IV값 크기로 bytes값(bytes * 8 = bits)
			};

			StreamCipherBASE()
				: _de_sch(), _impl()
			{}

			virtual ~StreamCipherBASE()
			{}					

			int initialize()
			{
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
		
			int initialize(const key_type &key)
			{
				return init(key, salm::static_bytes(IV_BYTES));
			}

			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief 복호화
			*
			*	\param src 복호화하고자 하는 내용
			*	\retval output_type 복호화된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				// 이 객체를 직접 사용할 수도 있는데, 초기화하지 않는 것을 방지한다.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_de_sch, &comp, sizeof(_de_sch)), "key is not initialized");
				
				output_type dst;
				if (!src.empty())
				{
					dst.resize(src.size());

					_impl.decrypt(_de_sch, dst, src, _ivector);
				}			

				return dst;
			}

			key_type			_userkey;			//!< 바이너리 키, 사용자가 복사하는 것을 허용한다.
			iv_type				_ivector;			//!< 바이너리 IV, 사용자가 복사하는 것을 허용한다.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// 키값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_decrypt(_de_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_de_sch;
			Algorithm			_impl;
		};

		// 기본 복호화모듈 형태
		// block cipher 복호화 알고리즘은 다음의 형태를 따른다.
		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV, std::size_t BC>
		struct BlockCipherBASE
		{
			typedef typename Algorithm::decrypt_input_type		input_type;
			typedef typename Algorithm::decrypt_output_type		output_type;		

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,				//KB는 키값 크기로 bytes값(bytes * 8 = bits로 모듈의 bit수를 결정함)
				IV_BYTES = IV,				//IV는 IV값 크기로 bytes값(bytes * 8 = bits)
				BLOCK_COUNT = BC,			//BC는 블록 bytes의 크기로 byte 개수, 패딩 bytes 개수에 사용된다.
			};

			BlockCipherBASE()
				: _de_sch(), _impl()
			{}

			virtual ~BlockCipherBASE()
			{}					
			
			int initialize()
			{
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
					
			int initialize(const key_type &key)
			{			
				return init(key, salm::static_bytes(IV_BYTES));
			}
			
			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief 복호화
			*
			*	\param src 복호화하고자 하는 내용
			*	\retval output_type 복호화된 배열을 리턴한다.
			*/
			output_type execute(const input_type &src)
			{
				// 이 객체를 직접 사용할 수도 있는데, 초기화하지 않는 것을 방지한다.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_de_sch, &comp, sizeof(_de_sch)), "key is not initialized");
				
				output_type dst;
				if (!src.empty())
				{								
					dst.resize(src.size());
					_impl.decrypt(_de_sch, dst, src, _ivector);
				
					// 사용자가 선택한 패딩 규칙이 적용된다.
					Padding padding;
					padding.remove<BLOCK_COUNT>(dst);
				}			

				return dst;
			}

			key_type		_userkey;			//!< 바이너리 키, 사용자가 복사하는 것을 허용한다.
			iv_type			_ivector;			//!< 바이너리 IV, 사용자가 복사하는 것을 허용한다.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// 키값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV값 크기가 다른 것을 금지한다. 크기(bytes)는 enum을 통해 제공하기 때문에 엄격하게 검사한다.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_decrypt(_de_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_de_sch;
			Algorithm			_impl;
		};
	}
}

#endif //__CIPHER_HPP