//	압축 알고리즘
//
//	공통특징
//    - 키는 존재하지 않는다.
//    - 무손실 압축만 지원하며, 압축된 데이터 크기는 커질 수도 있다.
//    - 대용량 데이터의 압축를 지원한다.
//    - 압축방식중 파일포맷은 지원하지 않는다.
//		- 참고 : 압축방식 = 파일포맷 + 압축 알고리즘
//
//	지원 알고리즘
//	- ZIP
//
//	인터페이스
//    - 서로 다른 압축 알고리즘은 다음의 인터페이스를 통해 동일하게 사용 가능하다.
//
//	개발방법
//	- 압축
//
//	//모듈 생성 및 초기화
//	crypto<encode::zip> encrypt;
//		
//	//압축실행
//	dst = encrypt.execute(src, src_size);		
//
//	- 복원
//
//	//모듈 생성 및 초기화
//	crypto<decode::zip> decrypt;
//		
//	//복원실행
//	dst = decrypt.execute(src, src_size);
//
//	리소스
//	- zlib-1.2.5
//
//	참고자료
//    - 압축 알고리즘 설명 : http://en.wikipedia.org/wiki/Data_compression
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