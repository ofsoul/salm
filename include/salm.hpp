// SALM Security Algorithms Module (SALM)
//	
//	소개
//	- Security Algorithms Module 은 여러 암호화 / 압축 알고리즘을 동일한 인터페이스를 통해 제공한다.
//	- 암호화 / 압축 알고리즘에 대한 추가적인 학습없이도 쉽게 사용할 수 있으며, 다양한 알고리즘을 제공한다.
//	
//	실행 및 빌드 환경
//	- Windows XP sp3 이상 (Win32 환경)
//	- Visual Studio 2008 C++
//	- zlib-1.2.5(소스 포함되어 있음)
//	- Boost 1.47.0이상(unittest 실행시 필요, SALM 라이브러리와는 무관)
//	- openssl-1.0.1c(라이브러리 포함되어 있음)
//	
//	구성요소
//	- 암호화 방식에 따라 3가지로 구성되어 있으며, 추가로 압축 알고리즘을 제공한다.
//	- Asymmetrics  : 비대칭키 알고리즘 모음
//	- Ciphers      : 대칭키 알고리즘 모음
//	- Digests      : 메시지 다이제스트 알고리즘 모음
//	- Compressions : 압축 알고리즘 모음 
//	- transforms   : 데이터 변환 알고리즘 모음 
//	
//	성능비교
//	- 암호화 알고리즘별 성능테스트 : http://www.cryptopp.com/benchmarks.html
//
//	테스트
//	- 주고받은 패킷에 이상이 없을시 응답시간을 찍어 문제가 발생하는지 체크했다.
//	- C# .net 4.0에서 제공하는 알고리즘으로 암호화후 바이너리값을 비교하였다.
//	- Boost 테스트 코드를 실행하려면, boost unittest 헤더와 라이브러리를 링크해야 한다.
//	\image html sosemanuk_2hour_test.gif "2시간 에코 테스트(sosemanuk)
//
//	그외
//	- 사용자 필요에 따라 부분 빌드할 수 있도록, 헤더 및 소스로만 제공되는 것을 목표로 한다.(openssl을 제외할 것이다.)
//	- openssl의 x64 libeay32.lib를 빌드할 수 없었다. 나머지 코드는 x64로 빌드 가능하지만, 실행은 보장할 수 없다.
//	- cmake를 통해 멀티 플래폼을 지원할 것이다.(gcc)
//	- C++0x은 권장사항이지만, std를 지원할 경우 사용할 수 있도록 할 것이다.
//	- byte_array를 위한 쓰레드 세이프한 allocator(가변 메모리풀)가 필요하다. 추가할 것이다.
//	- dll을 지원하지 않는다. boost xml같은 경량의 코드를 지향하기 때문이다.
#ifndef __SALM_HPP
#define __SALM_HPP

// 기본타입이다.
#ifndef byte
typedef unsigned char		byte;
#endif

// 빈타입이 필요했다.
struct EMPTY
{
	typedef	byte*			const_pointer;
};

#include <string>
#include <vector>

// allocator 추후 지원
// 쓰레드 세이프한, 가변 메모리풀이 필요하다.
typedef std::vector<byte>	byte_array;

#include <stdexcept>
#include <cassert>

// std를 기준으로 리팩토링하였지만, tr1이 기본은 아니다.
// 임시객체와 복사를 자주 사용하므로, Rvalue reference를 지원하는 C++0x 사용을 권장한다.
#if _HAS_CPP0X
#define salm_static_assert(_Expression, _Warning)	 static_assert(_Expression, _Warning)
#define salm_dynamic_assert(_Expression, _Warning)	 assert(_Expression)
#else /* _HAS_CPP0X */
#define salm_static_assert(_Expression, _Warning)	 assert(_Expression)
#define salm_dynamic_assert(_Expression, _Warning)	 assert(_Expression)
#endif /* _HAS_CPP0X */

namespace salm {

	// 에러를 리턴한 경우
	const int error = (-1);
	// 성공을 리턴한 경우
	const int success = (0);
	// 에러번호
	enum {
		UNKNOWN_ERROR = 0x00011000,			// 알 수 없는 에러
		INVALID_NO_DATA,					// 데이터가 없다.
		INVALID_BAD_MULTIPLE,				// 바이트가 선택한 배수로 나누어지지 않는다.
		INVALID_BAD_PADDING_BYTES,			// 패딩 바이트가 잘 못 되었다.
		INVALID_KEY_BYTES,					// 키의 바이트가 잘 못 되었다. 정확한 사용을 위해 엄격히 검사한다.
		INVALID_IV_BYTES,					// IV의 바이트가 잘 못 되었다. 정확한 사용을 위해 엄격히 검사한다.
		INVALID_DATA_SIZE,					// 데이터 크기가 잘 못 되었다.
	};

	// 에러번호를 리턴한다. 자세한 예외 상황은 what()을 통해 확인할 수 있다.
	class exception : public std::exception
	{
	public:
		exception(const char * const &);
		exception(const char * const &, int);
		int errcode();

	private:
		int _err;
	};

	//바이트값을 문자열로 치환한다.
	std::string bytes_to_string(const byte_array &ori);

	//문자열값을 바이트값로 치환한다.
	byte_array string_to_bytes(const std::string &ori);

	//입력한 크기만큼 랜덤한 값을 가지는 배열을 생성한다.
	byte_array generate_bytes(std::size_t n);	

	//입력한 크기만큼 정해진 값을 가지는 배열을 생성한다.
	byte_array static_bytes(std::size_t n);	

	// 동작하는 머신이 빅엔디안인지
	inline bool is_big_endian() 
	{
		unsigned short x = 1;
		return !(*reinterpret_cast<char*>(&x));
	}

	// 동작하는 머신이 리틀엔디안인지
	inline bool is_little_endian() 
	{
		return !is_big_endian();
	}
}

#endif //__SALM_HPP