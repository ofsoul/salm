//	���� �˰���
//
//	����Ư¡
//    - Ű�� �������� �ʴ´�.
//    - ���ս� ���ุ �����ϸ�, ����� ������ ũ��� Ŀ�� ���� �ִ�.
//    - ��뷮 �������� ���ฦ �����Ѵ�.
//    - �������� ���������� �������� �ʴ´�.
//		- ���� : ������ = �������� + ���� �˰���
//
//	���� �˰���
//	- ZIP
//
//	�������̽�
//    - ���� �ٸ� ���� �˰����� ������ �������̽��� ���� �����ϰ� ��� �����ϴ�.
//
//	���߹��
//	- ����
//
//	//��� ���� �� �ʱ�ȭ
//	crypto<encode::zip> encrypt;
//		
//	//�������
//	dst = encrypt.execute(src, src_size);		
//
//	- ����
//
//	//��� ���� �� �ʱ�ȭ
//	crypto<decode::zip> decrypt;
//		
//	//��������
//	dst = decrypt.execute(src, src_size);
//
//	���ҽ�
//	- zlib-1.2.5
//
//	�����ڷ�
//    - ���� �˰��� ���� : http://en.wikipedia.org/wiki/Data_compression
#ifndef __COMPRESSIONS_HPP
#define __COMPRESSIONS_HPP

#include "compressions/zip.hpp"

namespace salm {

	namespace encode {
		typedef CompressionBASE<zip_impl>				zip;
	}

	namespace decode {
		typedef CompressionBASE<zip_impl>				zip;
	}
}

#endif //__COMPRESSION_HPP