#ifndef __CIPHER_HPP
#define __CIPHER_HPP

#include "padding.hpp"

namespace salm {

	namespace encode {

		// �⺻ ��ȣȭ��� ����
		// stream cipher ��ȣȭ �˰����� ������ ���¸� ������.
		template <typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV>
		struct StreamCipherBASE
		{
			typedef typename Algorithm::encrypt_input_type	input_type;
			typedef typename Algorithm::encrypt_output_type	output_type;

			typedef typename Algorithm::key_type			key_type;
			typedef typename Algorithm::iv_type				iv_type;

			enum 
			{
				KEY_BYTES = KB,			//KB�� Ű�� ũ��� bytes��(bytes * 8 = bits�� ����� bit���� ������)
				IV_BYTES = IV,			//IV�� IV�� ũ��� bytes��(bytes * 8 = bits)
			};

			StreamCipherBASE()
				: _en_sch(), _impl()
			{}

			virtual ~StreamCipherBASE()
			{}		
			
			int initialize()
			{
				// �̱����� �����͸� �ְ� ���� ���, IV�� ���� �����ؾ� �ϸ� ���浵 �����ؾ� �Ѵ�.
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
		
			int initialize(const key_type &key)
			{
				// �̱����� �����͸� �ְ� ���� ���, IV�� ���� �����ؾ� �ϸ� ���浵 �����ؾ� �Ѵ�.
				return init(key, salm::static_bytes(IV_BYTES));
			}

			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief ��ȣȭ
			*		
			*	\param src ��ȣȭ�ϰ��� �ϴ� ����
			*	\retval output_type ��ȣȭ�� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				// �� ��ü�� ���� ����� ���� �ִµ�, �ʱ�ȭ���� �ʴ� ���� �����Ѵ�.
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

			key_type			_userkey;			//!< ���̳ʸ� Ű, ����ڰ� �����ϴ� ���� ����Ѵ�.
			iv_type				_ivector;			//!< ���̳ʸ� IV, ����ڰ� �����ϴ� ���� ����Ѵ�.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// Ű�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_encrypt(_en_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_en_sch;
			Algorithm			_impl;
		};

		// �⺻ ��ȣȭ��� ����
		// block cipher ��ȣȭ �˰����� ������ ���¸� ������.
		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV, std::size_t BC>
		struct BlockCipherBASE
		{
			typedef typename Algorithm::encrypt_input_type		input_type;
			typedef typename Algorithm::encrypt_output_type		output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,				//KB�� Ű�� ũ��� bytes��(bytes * 8 = bits�� ����� bit���� ������)
				IV_BYTES = IV,				//IV�� IV�� ũ��� bytes��(bytes * 8 = bits)
				BLOCK_COUNT = BC,			//BC�� ��� bytes�� ũ��� byte ����, �е� bytes ������ ���ȴ�.
			};

			BlockCipherBASE()
				: _en_sch(), _impl()
			{}

			virtual ~BlockCipherBASE()
			{}					
			
			int initialize()
			{
				// �̱����� �����͸� �ְ� ���� ���, IV�� ���� �����ؾ� �ϸ� ���浵 �����ؾ� �Ѵ�.
				return init(salm::generate_bytes(KEY_BYTES), salm::static_bytes(IV_BYTES));
			}
					
			int initialize(const key_type &key)
			{			
				// �̱����� �����͸� �ְ� ���� ���, IV�� ���� �����ؾ� �ϸ� ���浵 �����ؾ� �Ѵ�.
				return init(key, salm::static_bytes(IV_BYTES));
			}

			int initialize(const key_type &key, const iv_type &iv)
			{
				return init(key, iv);
			}

			/*! \brief ��ȣȭ
			*
			*	\param src ��ȣȭ�ϰ��� �ϴ� ����
			*	\retval output_type ��ȣȭ�� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				// �� ��ü�� ���� ����� ���� �ִµ�, �ʱ�ȭ���� �ʴ� ���� �����Ѵ�.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_en_sch, &comp, sizeof(_en_sch)), "key is not initialized");

				output_type dst;
				if (!src.empty())
				{
					// ����ڰ� ������ �е� ��Ģ�� ����ȴ�.
					Padding padding;
					input_type copy_i = src;
					padding.add<BLOCK_COUNT>(copy_i);
					dst.resize(copy_i.size());

					_impl.encrypt(_en_sch, dst, copy_i, _ivector);				
				}		

				return dst;
			}

			key_type		_userkey;			//!< ���̳ʸ� Ű, ����ڰ� �����ϴ� ���� ����Ѵ�.
			iv_type			_ivector;			//!< ���̳ʸ� IV	, ����ڰ� �����ϴ� ���� ����Ѵ�.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// Ű�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
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

		// �⺻ ��ȣȭ��� ����
		// stream cipher ��ȣȭ �˰����� ������ ���¸� ������.
		template <typename KEY_SCHEDULE, typename Algorithm,	std::size_t KB, std::size_t IV>
		struct StreamCipherBASE
		{
			typedef typename Algorithm::decrypt_input_type		input_type;
			typedef typename Algorithm::decrypt_output_type		output_type;

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,			//KB�� Ű�� ũ��� bytes��(bytes * 8 = bits�� ����� bit���� ������)
				IV_BYTES = IV,			//IV�� IV�� ũ��� bytes��(bytes * 8 = bits)
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

			/*! \brief ��ȣȭ
			*
			*	\param src ��ȣȭ�ϰ��� �ϴ� ����
			*	\retval output_type ��ȣȭ�� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				// �� ��ü�� ���� ����� ���� �ִµ�, �ʱ�ȭ���� �ʴ� ���� �����Ѵ�.
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

			key_type			_userkey;			//!< ���̳ʸ� Ű, ����ڰ� �����ϴ� ���� ����Ѵ�.
			iv_type				_ivector;			//!< ���̳ʸ� IV, ����ڰ� �����ϴ� ���� ����Ѵ�.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// Ű�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (iv.size() != IV_BYTES)		throw salm::exception("Is not equal to a fixed iv size", salm::INVALID_IV_BYTES);

				_userkey = key;
				_ivector = iv;

				_impl.init_decrypt(_de_sch, _userkey, _ivector);

				return salm::success;
			}

			KEY_SCHEDULE		_de_sch;
			Algorithm			_impl;
		};

		// �⺻ ��ȣȭ��� ����
		// block cipher ��ȣȭ �˰����� ������ ���¸� ������.
		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t IV, std::size_t BC>
		struct BlockCipherBASE
		{
			typedef typename Algorithm::decrypt_input_type		input_type;
			typedef typename Algorithm::decrypt_output_type		output_type;		

			typedef typename Algorithm::key_type				key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum 
			{
				KEY_BYTES = KB,				//KB�� Ű�� ũ��� bytes��(bytes * 8 = bits�� ����� bit���� ������)
				IV_BYTES = IV,				//IV�� IV�� ũ��� bytes��(bytes * 8 = bits)
				BLOCK_COUNT = BC,			//BC�� ��� bytes�� ũ��� byte ����, �е� bytes ������ ���ȴ�.
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

			/*! \brief ��ȣȭ
			*
			*	\param src ��ȣȭ�ϰ��� �ϴ� ����
			*	\retval output_type ��ȣȭ�� �迭�� �����Ѵ�.
			*/
			output_type execute(const input_type &src)
			{
				// �� ��ü�� ���� ����� ���� �ִµ�, �ʱ�ȭ���� �ʴ� ���� �����Ѵ�.
				KEY_SCHEDULE comp = {};
				salm_dynamic_assert(0 != std::memcmp(&_de_sch, &comp, sizeof(_de_sch)), "key is not initialized");
				
				output_type dst;
				if (!src.empty())
				{								
					dst.resize(src.size());
					_impl.decrypt(_de_sch, dst, src, _ivector);
				
					// ����ڰ� ������ �е� ��Ģ�� ����ȴ�.
					Padding padding;
					padding.remove<BLOCK_COUNT>(dst);
				}			

				return dst;
			}

			key_type		_userkey;			//!< ���̳ʸ� Ű, ����ڰ� �����ϴ� ���� ����Ѵ�.
			iv_type			_ivector;			//!< ���̳ʸ� IV, ����ڰ� �����ϴ� ���� ����Ѵ�.

		protected:

			int init(const key_type &key, const iv_type &iv)
			{
				// Ű�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
				if (key.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed key size", salm::INVALID_KEY_BYTES);
				// IV�� ũ�Ⱑ �ٸ� ���� �����Ѵ�. ũ��(bytes)�� enum�� ���� �����ϱ� ������ �����ϰ� �˻��Ѵ�.
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