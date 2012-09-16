//	메시지 다이제스트
//    
//	공통특징
//    - 키는 존재하지 않는다.
//    - 암호화시 고정 크기의 해쉬값을 반환한다.
//    - 복호화 과정은 존재하지 않는다.
//    - 대용량 데이터의 암호화를 지원한다.
//
//	지원 알고리즘
//	- MD5
//	- SHA1
//
//	인터페이스
//	- 서로 다른 메시지 다이제스트 알고리즘은 다음의 인터페이스를 통해 동일하게 사용 가능하다.
//
//	개발방법
//	- 암호화
//	
//	//모듈 생성
//	crypto<encode::md5::_128bit> encrypt;		
//		
//	//암호화
//	dst = encrypt.execute(src, src_size);
//	
//	리소스
//    - openssl-1.0.1c
//
//	참고자료
//    - 메시지 다이제스트 설명 : http://en.wikipedia.org/wiki/Cryptographic_hash_function
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