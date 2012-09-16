//	�޽��� ��������Ʈ
//    
//	����Ư¡
//    - Ű�� �������� �ʴ´�.
//    - ��ȣȭ�� ���� ũ���� �ؽ����� ��ȯ�Ѵ�.
//    - ��ȣȭ ������ �������� �ʴ´�.
//    - ��뷮 �������� ��ȣȭ�� �����Ѵ�.
//
//	���� �˰���
//	- MD5
//	- SHA1
//
//	�������̽�
//	- ���� �ٸ� �޽��� ��������Ʈ �˰����� ������ �������̽��� ���� �����ϰ� ��� �����ϴ�.
//
//	���߹��
//	- ��ȣȭ
//	
//	//��� ����
//	crypto<encode::md5::_128bit> encrypt;		
//		
//	//��ȣȭ
//	dst = encrypt.execute(src, src_size);
//	
//	���ҽ�
//    - openssl-1.0.1c
//
//	�����ڷ�
//    - �޽��� ��������Ʈ ���� : http://en.wikipedia.org/wiki/Cryptographic_hash_function
#ifndef __DIGESTS_HPP
#define __DIGESTS_HPP

#include "digests/md5.hpp"
#include "digests/sha.hpp"

namespace salm {

	namespace encode {

		namespace md5 {
			typedef DigestBASE<MD5_CTX, salm::md5::md5_impl, 16>		_128bit;
		}		

		namespace sha {
			typedef DigestBASE<SHA_CTX, salm::sha::sha160, 20>			_160bit;
			typedef DigestBASE<SHA256_CTX, salm::sha::sha256, 32>		_256bit;		
			typedef DigestBASE<SHA512_CTX, salm::sha::sha512, 64>		_512bit;
		}		
	
		/*! 
		* \} 
		*/
	}
}

#endif //__DIGESTS_HPP