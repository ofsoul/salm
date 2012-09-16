# Security Algorithms Module (SALM)

## 소개

* Security Algorithms Module 은 여러 암호화 / 압축 알고리즘을 동일한 인터페이스를 통해 제공한다.
* 암호화 / 압축 알고리즘에 대한 추가적인 학습없이도 쉽게 사용할 수 있으며, 다양한 알고리즘을 제공한다.

## 실행 및 빌드 환경

* Windows XP sp3 이상 (Win32 환경)
* Visual Studio 2008, 2010 C++ 에서 테스트
* zlib-1.2.5(소스 포함되어 있음)
* Boost 1.47.0, 1.51.0에서 테스트(unittest 실행시 필요, SALM 라이브러리와는 무관)
* openssl-1.0.1c(라이브러리 포함되어 있음)

## 구성요소

암호화 방식에 따라 3가지로 구성되어 있으며, 추가로 압축 알고리즘을 제공한다.
* Asymmetrics  : 비대칭키 알고리즘 모음
* Ciphers      : 대칭키 알고리즘 모음
* Digests      : 메시지 다이제스트 알고리즘 모음
* Compressions : 압축 알고리즘 모음 
* transforms   : 데이터 변환 알고리즘 모음 

## 성능비교

암호화 알고리즘별 성능테스트 : http://www.cryptopp.com/benchmarks.html

## 테스트

* 주고받은 패킷에 이상이 없을시 응답시간을 찍어 문제가 발생하는지 체크했다.
* C# .net 4.0에서 제공하는 알고리즘으로 암호화후 바이너리값을 비교하였다.
* Boost 테스트 코드를 실행하려면, boost unittest 헤더와 라이브러리를 링크해야 한다.

![screenshot](https://github.com/ofsoul/SALM/raw/master/sosemanuk_2hour_test.png)

## 사용방법

	const char *plantext = "12345678";

	byte_array key = salm::generate_bytes(encode::aes::_OFB128bit::KEY_BYTES);
	crypto<encode::aes::_OFB128bit> en(key);
	byte_array encrypt = en.execute((byte const*)plantext, strlen(plantext));

	crypto<decode::aes::_OFB128bit> de(key);
	byte_array decrypt = de.execute(encrypt);

## 그외

* 사용자 필요에 따라 부분 빌드할 수 있도록, 헤더 및 소스로만 제공되는 것을 목표로 한다.(openssl을 제외할 것이다.)
* openssl의 x64 libeay32.lib를 빌드할 수 없었다. 나머지 코드는 x64로 빌드 가능하지만, 실행은 보장할 수 없다.
* cmake를 통해 멀티 플래폼을 지원할 것이다.(gcc)
* C++0x은 권장사항이지만, std를 지원할 경우 사용할 수 있도록 할 것이다.
* byte_array를 위한 쓰레드 세이프한 allocator(가변 메모리풀)가 필요하다. 추가할 것이다.
* dll을 지원하지 않는다. boost xml같은 경량의 코드를 지향하기 때문이다.

## 라이센스

오픈 소스이다. 마음대로 사용가능하지만, 아직은 openssl을 사용하기때문에 다음이 적용된다.

License

This is a copy of the current LICENSE file inside the CVS repository.

  LICENSE ISSUES

  The OpenSSL toolkit stays under a dual license, i.e. both the conditions of
  the OpenSSL License and the original SSLeay license apply to the toolkit.
  See below for the actual license texts. Actually both licenses are BSD-style
  Open Source licenses. In case of any license issues related to OpenSSL
  please contact openssl-core@openssl.org.

  OpenSSL License

/* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

 Original SSLeay License

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */