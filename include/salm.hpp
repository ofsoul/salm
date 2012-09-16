// SALM Security Algorithms Module (SALM)
//	
//	�Ұ�
//	- Security Algorithms Module �� ���� ��ȣȭ / ���� �˰����� ������ �������̽��� ���� �����Ѵ�.
//	- ��ȣȭ / ���� �˰��� ���� �߰����� �н����̵� ���� ����� �� ������, �پ��� �˰����� �����Ѵ�.
//	
//	���� �� ���� ȯ��
//	- Windows XP sp3 �̻� (Win32 ȯ��)
//	- Visual Studio 2008 C++
//	- zlib-1.2.5(�ҽ� ���ԵǾ� ����)
//	- Boost 1.47.0�̻�(unittest ����� �ʿ�, SALM ���̺귯���ʹ� ����)
//	- openssl-1.0.1c(���̺귯�� ���ԵǾ� ����)
//	
//	�������
//	- ��ȣȭ ��Ŀ� ���� 3������ �����Ǿ� ������, �߰��� ���� �˰����� �����Ѵ�.
//	- Asymmetrics  : ���ĪŰ �˰��� ����
//	- Ciphers      : ��ĪŰ �˰��� ����
//	- Digests      : �޽��� ��������Ʈ �˰��� ����
//	- Compressions : ���� �˰��� ���� 
//	- transforms   : ������ ��ȯ �˰��� ���� 
//	
//	���ɺ�
//	- ��ȣȭ �˰��� �����׽�Ʈ : http://www.cryptopp.com/benchmarks.html
//
//	�׽�Ʈ
//	- �ְ���� ��Ŷ�� �̻��� ������ ����ð��� ��� ������ �߻��ϴ��� üũ�ߴ�.
//	- C# .net 4.0���� �����ϴ� �˰������� ��ȣȭ�� ���̳ʸ����� ���Ͽ���.
//	- Boost �׽�Ʈ �ڵ带 �����Ϸ���, boost unittest ����� ���̺귯���� ��ũ�ؾ� �Ѵ�.
//	\image html sosemanuk_2hour_test.gif "2�ð� ���� �׽�Ʈ(sosemanuk)
//
//	�׿�
//	- ����� �ʿ信 ���� �κ� ������ �� �ֵ���, ��� �� �ҽ��θ� �����Ǵ� ���� ��ǥ�� �Ѵ�.(openssl�� ������ ���̴�.)
//	- openssl�� x64 libeay32.lib�� ������ �� ������. ������ �ڵ�� x64�� ���� ����������, ������ ������ �� ����.
//	- cmake�� ���� ��Ƽ �÷����� ������ ���̴�.(gcc)
//	- C++0x�� �������������, std�� ������ ��� ����� �� �ֵ��� �� ���̴�.
//	- byte_array�� ���� ������ �������� allocator(���� �޸�Ǯ)�� �ʿ��ϴ�. �߰��� ���̴�.
//	- dll�� �������� �ʴ´�. boost xml���� �淮�� �ڵ带 �����ϱ� �����̴�.
#ifndef __SALM_HPP
#define __SALM_HPP

// �⺻Ÿ���̴�.
#ifndef byte
typedef unsigned char		byte;
#endif

// ��Ÿ���� �ʿ��ߴ�.
struct EMPTY
{
	typedef	byte*			const_pointer;
};

#include <string>
#include <vector>

// allocator ���� ����
// ������ ��������, ���� �޸�Ǯ�� �ʿ��ϴ�.
typedef std::vector<byte>	byte_array;

#include <stdexcept>
#include <cassert>

// std�� �������� �����丵�Ͽ�����, tr1�� �⺻�� �ƴϴ�.
// �ӽð�ü�� ���縦 ���� ����ϹǷ�, Rvalue reference�� �����ϴ� C++0x ����� �����Ѵ�.
#if _HAS_CPP0X
#define salm_static_assert(_Expression, _Warning)	 static_assert(_Expression, _Warning)
#define salm_dynamic_assert(_Expression, _Warning)	 assert(_Expression)
#else /* _HAS_CPP0X */
#define salm_static_assert(_Expression, _Warning)	 assert(_Expression)
#define salm_dynamic_assert(_Expression, _Warning)	 assert(_Expression)
#endif /* _HAS_CPP0X */

namespace salm {

	// ������ ������ ���
	const int error = (-1);
	// ������ ������ ���
	const int success = (0);
	// ������ȣ
	enum {
		UNKNOWN_ERROR = 0x00011000,			// �� �� ���� ����
		INVALID_NO_DATA,					// �����Ͱ� ����.
		INVALID_BAD_MULTIPLE,				// ����Ʈ�� ������ ����� ���������� �ʴ´�.
		INVALID_BAD_PADDING_BYTES,			// �е� ����Ʈ�� �� �� �Ǿ���.
		INVALID_KEY_BYTES,					// Ű�� ����Ʈ�� �� �� �Ǿ���. ��Ȯ�� ����� ���� ������ �˻��Ѵ�.
		INVALID_IV_BYTES,					// IV�� ����Ʈ�� �� �� �Ǿ���. ��Ȯ�� ����� ���� ������ �˻��Ѵ�.
		INVALID_DATA_SIZE,					// ������ ũ�Ⱑ �� �� �Ǿ���.
	};

	// ������ȣ�� �����Ѵ�. �ڼ��� ���� ��Ȳ�� what()�� ���� Ȯ���� �� �ִ�.
	class exception : public std::exception
	{
	public:
		exception(const char * const &);
		exception(const char * const &, int);
		int errcode();

	private:
		int _err;
	};

	//����Ʈ���� ���ڿ��� ġȯ�Ѵ�.
	std::string bytes_to_string(const byte_array &ori);

	//���ڿ����� ����Ʈ���� ġȯ�Ѵ�.
	byte_array string_to_bytes(const std::string &ori);

	//�Է��� ũ�⸸ŭ ������ ���� ������ �迭�� �����Ѵ�.
	byte_array generate_bytes(std::size_t n);	

	//�Է��� ũ�⸸ŭ ������ ���� ������ �迭�� �����Ѵ�.
	byte_array static_bytes(std::size_t n);	

	// �����ϴ� �ӽ��� �򿣵������
	inline bool is_big_endian() 
	{
		unsigned short x = 1;
		return !(*reinterpret_cast<char*>(&x));
	}

	// �����ϴ� �ӽ��� ��Ʋ���������
	inline bool is_little_endian() 
	{
		return !is_big_endian();
	}
}

#endif //__SALM_HPP