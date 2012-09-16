//	��ĪŰ �˰���
//
//	����Ư¡
//    - Ű�� 1�� �����Ѵ�.
//    - ����ڰ� ���Ƿ� Ű�� ���� �� �ִ�.
//    - ��뷮 �������� ��ȣȭ�� �����Ѵ�.
//    - ��ȣȭ�� ������ ũ�Ⱑ ��Ī�� stream����� �����Ѵ�.
//		- ���� : ��ȣȭ�� ��Ʈ�� ���� ��Ʈ���� ������ �شٴ� bit stream�� ������ �ǹ�����, stream����� �� �ٸ� Ư¡�̴�.
//    - ��ȣȭ�� ������ ũ�Ⱑ ���Ī�� block����� �����Ѵ�.
//		- ���� : CFB, OFB ���� ������ ũ�Ⱑ ����.
//    - �Ϲ������� block��ĺ��� stream�����, ��ȣȭ ������ �������� ������.
//
//	���� �˰���
//	- block
//      - AES
//    	- DES
//    	- SEED
//	- stream
//    	- GRAIN
//    	- HC
//    	- MICKEY
//    	- RABBIT
//    	- RC4
//    	- SALSA20
//    	- SOSEMANUK
//    
//	�������̽�
//    - ���� �ٸ� ��ĪŰ �˰����� ������ �������̽��� ���� �����ϰ� ��� �����ϴ�.
//
//	���߹��
//	- ��ȣȭ
//
//	//��� ���� �� Ű�Է�
//	crypto<encode::des::_ECB64bit> encrypt(key);
//		
//	//��ȣȭ
//	dst = encrypt.execute(src, src_size);
//
//	- ��ȣȭ
//
//	//��� ���� �� Ű�Է�
//	crypto<decode::des::_ECB64bit> decrypt(key);
//		
//	//��ȣȭ
//	dst = decrypt.execute(src, src_size);
//		
//	���ҽ�
//    - openssl-1.0.1c
//    - the eStream Project
//
//	�����ڷ�
//    - ����� ��ĪŰ ���� : http://en.wikipedia.org/wiki/Block_cipher
//    - ��Ʈ���� ��ĪŰ ���� : http://en.wikipedia.org/wiki/Stream_cipher
#ifndef __CIPHERS_HPP
#define __CIPHERS_HPP

#include "ciphers/sosemanuk.hpp"
#include "ciphers/salsa20.hpp"
#include "ciphers/rc4.hpp"
#include "ciphers/rabbit.hpp"
#include "ciphers/mickey.hpp"
#include "ciphers/hc.hpp"
#include "ciphers/grain.hpp"
#include "ciphers/seed.hpp"
#include "ciphers/des.hpp"
#include "ciphers/aes.hpp"

namespace salm {

	namespace encode {

		namespace sosemanuk {
			typedef StreamCipherBASE<SOSEMANUK_ECRYPT_ctx, salm::sosemanuk::sosemanuk256, 32, 8>		_256bit;
		}
		namespace salsa20 {
			typedef StreamCipherBASE<SALSA20_ECRYPT_ctx, salm::salsa20::salsa20_256, 32, 8>				_256bit;
		}
		namespace rc4 {
			typedef StreamCipherBASE<RC4_KEY, salm::rc4::rc4_128, 16, 8>								_128bit;
		}
		namespace rabbit {
			typedef StreamCipherBASE<RABBIT_ECRYPT_ctx, salm::rabbit::rabbit128, 16, 8>					_128bit;
		}
		namespace mickey {
			typedef StreamCipherBASE<MICKEY128_ECRYPT_ctx, salm::mickey::mickey128, 16, 16>				_128bit;
		}
		namespace hc {
			typedef StreamCipherBASE<HC128_ECRYPT_ctx, salm::hc::hc128, 16, 8>							_128bit;
		}
		namespace grain {
			typedef StreamCipherBASE<GRAIN_ECRYPT_ctx, salm::grain::grain80, 10, 8>						_80bit;
		}
		namespace seed {
			template <typename Padding> struct ECB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::ecb128, 16, 16, 16> {};
			template <typename Padding> struct CBC128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::cbc128, 16, 16, 16> {};
			template <typename Padding> struct CFB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::cfb128, 16, 16, 16> {};
			template <typename Padding> struct OFB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::ofb128, 16, 16, 16> {};

			typedef ECB128<salm::padding::PKCS7>			_ECB128bit;
			typedef CBC128<salm::padding::PKCS7>			_CBC128bit;
			typedef CFB128<salm::padding::NONE>				_CFB128bit;
			typedef OFB128<salm::padding::NONE>				_OFB128bit;
		}
		namespace des {
			template <typename Padding> struct ECB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::ecb64, 8, 8, 8> {};
			template <typename Padding> struct CBC64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::cbc64, 8, 8, 8> {};
			template <typename Padding> struct CFB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::cfb64, 8, 8, 8> {};
			template <typename Padding> struct OFB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::ofb64, 8, 8, 8> {};

			typedef ECB64<salm::padding::PKCS7>				_ECB64bit;
			typedef CBC64<salm::padding::PKCS7>				_CBC64bit;
			typedef CFB64<salm::padding::NONE>				_CFB64bit;
			typedef OFB64<salm::padding::NONE>				_OFB64bit;
		}
		namespace aes {
			template <typename Padding> struct ECB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 16, 16, 16> {};
			template <typename Padding> struct CBC128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 16, 16, 16> {};
			template <typename Padding> struct CFB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 16, 16, 16> {};
			template <typename Padding> struct OFB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 16, 16, 16> {};

			template <typename Padding> struct ECB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 24, 16, 16> {};
			template <typename Padding> struct CBC192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 24, 16, 16> {};
			template <typename Padding> struct CFB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 24, 16, 16> {};
			template <typename Padding> struct OFB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 24, 16, 16> {};

			template <typename Padding> struct ECB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 32, 16, 16> {};
			template <typename Padding> struct CBC256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 32, 16, 16> {};
			template <typename Padding> struct CFB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 32, 16, 16> {};
			template <typename Padding> struct OFB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 32, 16, 16> {};

			typedef ECB128<salm::padding::PKCS7>			_ECB128bit;
			typedef CBC128<salm::padding::PKCS7>			_CBC128bit;
			typedef CFB128<salm::padding::NONE>				_CFB128bit;
			typedef OFB128<salm::padding::NONE>				_OFB128bit;

			typedef ECB192<salm::padding::PKCS7>			_ECB192bit;
			typedef CBC192<salm::padding::PKCS7>			_CBC192bit;
			typedef CFB192<salm::padding::NONE>				_CFB192bit;
			typedef OFB192<salm::padding::NONE>				_OFB192bit;

			typedef ECB256<salm::padding::PKCS7>			_ECB256bit;
			typedef CBC256<salm::padding::PKCS7>			_CBC256bit;
			typedef CFB256<salm::padding::NONE>				_CFB256bit;
			typedef OFB256<salm::padding::NONE>				_OFB256bit;
		}
	}

	namespace decode {

		namespace sosemanuk {
			typedef StreamCipherBASE<SOSEMANUK_ECRYPT_ctx, salm::sosemanuk::sosemanuk256, 32, 8>		_256bit;
		}
		namespace salsa20 {
			typedef StreamCipherBASE<SALSA20_ECRYPT_ctx, salm::salsa20::salsa20_256, 32, 8>				_256bit;
		}
		namespace rc4 {
			typedef StreamCipherBASE<RC4_KEY, salm::rc4::rc4_128, 16, 8>								_128bit;
		}
		namespace rabbit {
			typedef StreamCipherBASE<RABBIT_ECRYPT_ctx, salm::rabbit::rabbit128, 16, 8>					_128bit;
		}
		namespace mickey {
			typedef StreamCipherBASE<MICKEY128_ECRYPT_ctx, salm::mickey::mickey128, 16, 16>				_128bit;
		}
		namespace hc {
			typedef StreamCipherBASE<HC128_ECRYPT_ctx, salm::hc::hc128, 16, 8>							_128bit;
		}
		namespace grain {
			typedef StreamCipherBASE<GRAIN_ECRYPT_ctx, salm::grain::grain80, 10, 8>						_80bit;
		}
		namespace seed {
			template <typename Padding> struct ECB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::ecb128, 16, 16, 16> {};
			template <typename Padding> struct CBC128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::cbc128, 16, 16, 16> {};
			template <typename Padding> struct CFB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::cfb128, 16, 16, 16> {};
			template <typename Padding> struct OFB128 : public BlockCipherBASE<Padding, SEED_KEY_SCHEDULE, salm::seed::ofb128, 16, 16, 16> {};

			typedef ECB128<salm::padding::PKCS7>			_ECB128bit;
			typedef CBC128<salm::padding::PKCS7>			_CBC128bit;
			typedef CFB128<salm::padding::NONE>				_CFB128bit;
			typedef OFB128<salm::padding::NONE>				_OFB128bit;
		}
		namespace des {			
			template <typename Padding> struct ECB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::ecb64, 8, 8, 8> {};
			template <typename Padding> struct CBC64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::cbc64, 8, 8, 8> {};
			template <typename Padding> struct CFB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::cfb64, 8, 8, 8> {};
			template <typename Padding> struct OFB64 : public BlockCipherBASE<Padding, DES_key_schedule, salm::des::ofb64, 8, 8, 8> {};

			typedef ECB64<salm::padding::PKCS7>				_ECB64bit;
			typedef CBC64<salm::padding::PKCS7>				_CBC64bit;
			typedef CFB64<salm::padding::NONE>				_CFB64bit;
			typedef OFB64<salm::padding::NONE>				_OFB64bit;
		}
		namespace aes {
			template <typename Padding> struct ECB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 16, 16, 16> {};
			template <typename Padding> struct CBC128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 16, 16, 16> {};
			template <typename Padding> struct CFB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 16, 16, 16> {};
			template <typename Padding> struct OFB128 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 16, 16, 16> {};

			template <typename Padding> struct ECB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 24, 16, 16> {};
			template <typename Padding> struct CBC192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 24, 16, 16> {};
			template <typename Padding> struct CFB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 24, 16, 16> {};
			template <typename Padding> struct OFB192 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 24, 16, 16> {};

			template <typename Padding> struct ECB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ecb, 32, 16, 16> {};
			template <typename Padding> struct CBC256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cbc, 32, 16, 16> {};
			template <typename Padding> struct CFB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::cfb, 32, 16, 16> {};
			template <typename Padding> struct OFB256 : public BlockCipherBASE<Padding, AES_KEY, salm::aes::ofb, 32, 16, 16> {};

			typedef ECB128<salm::padding::PKCS7>			_ECB128bit;
			typedef CBC128<salm::padding::PKCS7>			_CBC128bit;
			typedef CFB128<salm::padding::NONE>				_CFB128bit;
			typedef OFB128<salm::padding::NONE>				_OFB128bit;

			typedef ECB192<salm::padding::PKCS7>			_ECB192bit;
			typedef CBC192<salm::padding::PKCS7>			_CBC192bit;
			typedef CFB192<salm::padding::NONE>				_CFB192bit;
			typedef OFB192<salm::padding::NONE>				_OFB192bit;

			typedef ECB256<salm::padding::PKCS7>			_ECB256bit;
			typedef CBC256<salm::padding::PKCS7>			_CBC256bit;
			typedef CFB256<salm::padding::NONE>				_CFB256bit;
			typedef OFB256<salm::padding::NONE>				_OFB256bit;
		}
	}
}

#endif //__CIPHERS_HPP