//	Data Transform
//    
//	����Ư¡
//    - Ű�� �������� �ʴ´�.
//    - ���ڵ��� ���ڵ� �������� ũ��� ����.
//    - ���ڵ������ ASCII���ڿ��̸�, ���ڵ� ����� ����Ʈ �迭�̴�.
//    - ��뷮 �������� ���ڵ��� �����Ѵ�.
//
//	���� �˰���
//	- BASE64
//
//	�������̽�
//	- ���� �ٸ� Data Transform �˰����� ������ �������̽��� ���� �����ϰ� ��� �����ϴ�.
//
//	���߹��
//	- ��ȣȭ
//
//	//��� ����
//	crypto<encode::base64> encrypt;
//		
//	//���ڵ�
//	dst = encrypt.execute(src, src_size);
//
//	- ��ȣȭ
//
//	//��� ����
//	crypto<decode::base64> decrypt;
//		
//	//���ڵ�
//	dst = decrypt.execute(src, src_size);
//
//	�����ڷ�
//    - base64 �ڵ� : https://github.com/ReneNyffenegger/development_misc/tree/master/base64
#ifndef __TRANSFORMS_HPP
#define __TRANSFORMS_HPP

#include "transforms\base64.hpp"

namespace salm {

	namespace encode {

		typedef TransformBASE<salm::base64_impl>		base64;
	}

	namespace decode {

		typedef TransformBASE<salm::base64_impl>		base64;
	}
}

#endif //__TRANSFORMS_HPP