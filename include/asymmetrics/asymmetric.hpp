#ifndef __ASYMMETRIC_HPP
#define __ASYMMETRIC_HPP

namespace salm {		

	namespace encode {

		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t BC>
		struct AsymmetricBASE
		{
			typedef typename Algorithm::encrypt_input_type		input_type;
			typedef typename Algorithm::encrypt_output_type		output_type;

			typedef typename Algorithm::public_key_type			key_type;
			typedef typename Algorithm::iv_type					iv_type;

			enum {
				BLOCK_COUNT = BC,
				KEY_BYTES = KB,
			};

			AsymmetricBASE()
				: _en_sch(0), _impl()
			{}

			virtual ~AsymmetricBASE()
			{
				key_reset();
			}

			/*! \brief �ʱ�ȭ
			*
			*	\exception salm::INVALID_KEY_SIZE Ű ũ�Ⱑ �ٸ� ���
			*/
			int initialize(const key_type &key)
			{
				key_reset(_impl.init_encrypt_key(_user_key = key, KEY_BYTES));
				return salm::success;
			}

			/*! \brief ��ȣȭ
			*		
			*	\exception salm::INVALID_BAD_MULTIPLE src�� BLOCK_SIZE�� ����� �ƴ� ���
			*	\remark BLOCK_SIZE ����Ʈ ������ ��ȣȭ�Ѵ�.
			*			���� ��ȣȭ ���� ���� ��ȣȭ ���� ������ �� ���� �ִ�.
			*/
			output_type execute(const input_type &src)
			{
				salm_dynamic_assert(0 != _en_sch, "key is not initialized");

				output_type dst;
				if (!src.empty())
				{				
					if (src.size() > KEY_BYTES - BLOCK_COUNT) throw salm::exception("Is not equal to a fixed data size", salm::INVALID_DATA_SIZE);

					dst.resize(KEY_BYTES);
					_impl.public_encrypt<Padding>(dst, src, _en_sch);
				}			

				return dst;
			}			

			key_type	_user_key;			//!< ���̳ʸ� Ű

		protected:

			void key_reset(KEY_SCHEDULE* ptr = 0) {
				if (_en_sch != ptr) {
					_impl.release_encrypt_key(_en_sch);
					_en_sch = ptr;
				}
			}

			KEY_SCHEDULE		*_en_sch;
			Algorithm			_impl;
		};
	}

	namespace decode {

		template <typename Padding, typename KEY_SCHEDULE, typename Algorithm, std::size_t KB, std::size_t BC>
		struct AsymmetricBASE
		{
			typedef typename Algorithm::decrypt_input_type		input_type;
			typedef typename Algorithm::decrypt_output_type		output_type;
			typedef typename Algorithm::private_key_type		key_type;

			typedef typename Algorithm::iv_type					iv_type;

			enum {
				BLOCK_COUNT = BC,
				KEY_BYTES = KB,
			};

			AsymmetricBASE()
				: _de_sch(0), _impl()
			{}

			virtual ~AsymmetricBASE()
			{
				key_reset();
			}

			/*! \brief �ʱ�ȭ
			*
			*	\exception salm::INVALID_KEY_SIZE Ű ũ�Ⱑ �ٸ� ���
			*/
			int initialize(const key_type &key)
			{
				key_reset(_impl.init_decrypt_key(_user_key = key, KEY_BYTES));
				return salm::success;
			}		

			/*! \brief ��ȣȭ
			*
			*	\exception salm::INVALID_BAD_MULTIPLE src�� BLOCK_SIZE�� ����� �ƴ� ���
			*	\remark BLOCK_SIZE ����Ʈ ������ ��ȣȭ�Ѵ�.
			*			���� ��ȣȭ ���� ���� ��ȣȭ ���� ������ �� ���� �ִ�.
			*/
			output_type execute(const input_type &src)
			{			
				salm_dynamic_assert(0 != _de_sch, "key is not initialized");
				
				output_type dst;
				if (!src.empty())
				{
					if (src.size() != KEY_BYTES)	throw salm::exception("Is not equal to a fixed data size", salm::INVALID_DATA_SIZE);

					Padding padding;
					dst.resize(src.size());
					_impl.private_decrypt<Padding>(dst, src, _de_sch);
				}			

				return dst;
			}

			key_type	_user_key;			//!< ���̳ʸ� Ű

		protected:

			void key_reset(KEY_SCHEDULE* ptr = 0) {
				if (_de_sch != ptr) {
					_impl.release_decrypt_key(_de_sch);
					_de_sch = ptr;
				}
			}

			KEY_SCHEDULE		*_de_sch;
			Algorithm			_impl;
		};
	}
}

#endif //__ASYMMETRIC_HPP