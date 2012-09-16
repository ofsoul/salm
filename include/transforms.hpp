//	Data Transform
//    
//	공통특징
//    - 키는 존재하지 않는다.
//    - 인코딩과 디코딩 데이터의 크기는 같다.
//    - 인코딩결과는 ASCII문자열이며, 디코딩 결과는 바이트 배열이다.
//    - 대용량 데이터의 인코딩을 지원한다.
//
//	지원 알고리즘
//	- BASE64
//
//	인터페이스
//	- 서로 다른 Data Transform 알고리즘은 다음의 인터페이스를 통해 동일하게 사용 가능하다.
//
//	개발방법
//	- 암호화
//
//	//모듈 생성
//	crypto<encode::base64> encrypt;
//		
//	//인코딩
//	dst = encrypt.execute(src, src_size);
//
//	- 복호화
//
//	//모듈 생성
//	crypto<decode::base64> decrypt;
//		
//	//디코딩
//	dst = decrypt.execute(src, src_size);
//
//	참고자료
//    - base64 코드 : https://github.com/ReneNyffenegger/development_misc/tree/master/base64
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