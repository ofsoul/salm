/*
 * REFERENCE IMPLEMENTATION OF STREAM CIPHER GRAIN VERSION 1
 *
 * Filename: grain.h
 *
 * Author:
 * Martin Hell
 * Dept. of Information Technology
 * P.O. Box 118
 * SE-221 00 Lund, Sweden,
 * email: martin@it.lth.se
 *
 * Synopsis:
 *  Header file for grain.c
 *
 */

/* ecrypt-sync.h */

/* 
* Header file for synchronous stream ciphers without authentication
* mechanism.
* 
* *** Please only edit parts marked with "[edit]". ***
*/

#ifndef __ECRYPT_GRAIN_H
#define __ECRYPT_GRAIN_H

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
* The name of your cipher.
*/
#define GRAIN_ECRYPT_NAME		"ECRYPT Stream Cipher"    /* [edit] */ 
#define GRAIN_ECRYPT_PROFILE	"HW"
/*
* Specify which key and IV sizes are supported by your cipher. A user
* should be able to enumerate the supported sizes by running the
* following code:
*
* for (i = 0; ECRYPT_KEYSIZE(i) <= ECRYPT_MAXKEYSIZE; ++i)
*   {
*     keysize = ECRYPT_KEYSIZE(i);
*
*     ...
*   }
*
* All sizes are in bits.
*/

#define GRAIN_ECRYPT_MAXKEYSIZE 80                 /* [edit] */
#define GRAIN_ECRYPT_KEYSIZE(i) (80 + (i)*32)      /* [edit] */

#define GRAIN_ECRYPT_MAXIVSIZE 64                   /* [edit] */
#define GRAIN_ECRYPT_IVSIZE(i) (64 + (i)*64)        /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
* ECRYPT_ctx is the structure containing the representation of the
* internal state of your cipher. 
*/

typedef struct
{
	u32 LFSR[80];
	u32 NFSR[80];
	const u8* p_key;
	u32 keysize;
	u32 ivsize;

} GRAIN_ECRYPT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
* Key and message independent initialization. This function will be
* called once when the program starts (e.g., to build expanded S-box
* tables).
*/
void GRAIN_ECRYPT_init();

/*
* Key setup. It is the user's responsibility to select the values of
* keysize and ivsize from the set of supported values specified
* above.
*/
void GRAIN_ECRYPT_keysetup(
					 GRAIN_ECRYPT_ctx* ctx, 
					 const u8* key, 
					 u32 keysize,                /* Key size in bits. */ 
					 u32 ivsize);                /* IV size in bits. */ 

/*
* IV setup. After having called ECRYPT_keysetup(), the user is
* allowed to call ECRYPT_ivsetup() different times in order to
* encrypt/decrypt different messages with the same key but different
* IV's.
*/
void GRAIN_ECRYPT_ivsetup(
					GRAIN_ECRYPT_ctx* ctx, 
					const u8* iv);

/*
* Encryption/decryption of arbitrary length messages.
*
* For efficiency reasons, the API provides two types of
* encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
* (declared here) encrypts byte strings of arbitrary length, while
* the ECRYPT_encrypt_blocks() function (defined later) only accepts
* lengths which are multiples of ECRYPT_BLOCKLENGTH.
* 
* The user is allowed to make multiple calls to
* ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
* but he is NOT allowed to make additional encryption calls once he
* has called ECRYPT_encrypt_bytes() (unless he starts a new message
* of course). For example, this sequence of calls is acceptable:
*
* ECRYPT_keysetup();
*
* ECRYPT_ivsetup();
* ECRYPT_encrypt_blocks();
* ECRYPT_encrypt_blocks();
* ECRYPT_encrypt_bytes();
*
* ECRYPT_ivsetup();
* ECRYPT_encrypt_blocks();
* ECRYPT_encrypt_blocks();
*
* ECRYPT_ivsetup();
* ECRYPT_encrypt_bytes();
* 
* The following sequence is not:
*
* ECRYPT_keysetup();
* ECRYPT_ivsetup();
* ECRYPT_encrypt_blocks();
* ECRYPT_encrypt_bytes();
* ECRYPT_encrypt_blocks();
*/

void GRAIN_ECRYPT_encrypt_bytes(
						  GRAIN_ECRYPT_ctx* ctx, 
						  const u8* plaintext, 
						  u8* ciphertext, 
						  u32 msglen);                /* Message length in bytes. */ 

void GRAIN_ECRYPT_decrypt_bytes(
						  GRAIN_ECRYPT_ctx* ctx, 
						  const u8* ciphertext, 
						  u8* plaintext, 
						  u32 msglen);                /* Message length in bytes. */ 

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
* For testing purposes it can sometimes be useful to have a function
* which immediately generates keystream without having to provide it
* with a zero plaintext. If your cipher cannot provide this function
* (e.g., because it is not strictly a synchronous cipher), please
* reset the ECRYPT_GENERATES_KEYSTREAM flag.
*/

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

void GRAIN_ECRYPT_keystream_bytes(
							GRAIN_ECRYPT_ctx* ctx,
							u8* keystream,
							u32 length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional optimizations */

/* 
* By default, the functions in this section are implemented using
* calls to functions declared above. However, you might want to
* implement them differently for performance reasons.
*/

/*
* All-in-one encryption/decryption of (short) packets.
*
* The default definitions of these functions can be found in
* "ecrypt-sync.c". If you want to implement them differently, please
* undef the ECRYPT_USES_DEFAULT_ALL_IN_ONE flag.
*/
#define GRAIN_ECRYPT_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

void GRAIN_ECRYPT_encrypt_packet(
						   GRAIN_ECRYPT_ctx* ctx, 
						   const u8* iv,
						   const u8* plaintext, 
						   u8* ciphertext, 
						   u32 msglen);

void GRAIN_ECRYPT_decrypt_packet(
						   GRAIN_ECRYPT_ctx* ctx, 
						   const u8* iv,
						   const u8* ciphertext, 
						   u8* plaintext, 
						   u32 msglen);

/*
* Encryption/decryption of blocks.
* 
* By default, these functions are defined as macros. If you want to
* provide a different implementation, please undef the
* ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
* declared below.
*/

#define GRAIN_ECRYPT_BLOCKLENGTH 4                  /* [edit] */

#define GRAIN_ECRYPT_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef GRAIN_ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define GRAIN_ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
	GRAIN_ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
	(blocks) * GRAIN_ECRYPT_BLOCKLENGTH)

#define GRAIN_ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
	GRAIN_ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
	(blocks) * GRAIN_ECRYPT_BLOCKLENGTH)

#ifdef GRAIN_ECRYPT_GENERATES_KEYSTREAM

#define GRAIN_ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
	GRAIN_ECRYPT_AE_keystream_bytes(ctx, keystream,                        \
	(blocks) * GRAIN_ECRYPT_BLOCKLENGTH)

#endif

#else

void GRAIN_ECRYPT_encrypt_blocks(
						   GRAIN_ECRYPT_ctx* ctx, 
						   const u8* plaintext, 
						   u8* ciphertext, 
						   u32 blocks);                /* Message length in blocks. */ 

void GRAIN_ECRYPT_decrypt_blocks(
						   GRAIN_ECRYPT_ctx* ctx, 
						   const u8* ciphertext, 
						   u8* plaintext, 
						   u32 blocks);                /* Message length in blocks. */ 

#ifdef GRAIN_ECRYPT_GENERATES_KEYSTREAM

void GRAIN_ECRYPT_keystream_blocks(
							 GRAIN_ECRYPT_AE_ctx* ctx,
							 const u8* keystream,
							 u32 blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/*
* If your cipher can be implemented in different ways, you can use
* the ECRYPT_VARIANT parameter to allow the user to choose between
* them at compile time (e.g., gcc -DECRYPT_VARIANT=3 ...). Please
* only use this possibility if you really think it could make a
* significant difference and keep the number of variants
* (ECRYPT_MAXVARIANT) as small as possible (definitely not more than
* 10). Note also that all variants should have exactly the same
* external interface (i.e., the same ECRYPT_BLOCKLENGTH, etc.). 
*/
#define GRAIN_ECRYPT_MAXVARIANT 1                   /* [edit] */

#ifndef GRAIN_ECRYPT_VARIANT
#define GRAIN_ECRYPT_VARIANT 1
#endif

#if (GRAIN_ECRYPT_VARIANT > GRAIN_ECRYPT_MAXVARIANT)
#error this variant does not exist
#endif

/* ------------------------------------------------------------------------- */

#define INITCLOCKS 160
#define N(i) (ctx->NFSR[80-i])
#define L(i) (ctx->LFSR[80-i])
#define X0 (ctx->LFSR[3])
#define X1 (ctx->LFSR[25])
#define X2 (ctx->LFSR[46])
#define X3 (ctx->LFSR[64])
#define X4 (ctx->NFSR[63])

static const u8 NFTable[1024]= {0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,0,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,1,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
		1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,1,1,1,0,1,1,1,1,
		0,1,0,0,1,0,1,1,1,1,1,0,0,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,1,1,1,1,
		1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
		0,1,0,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,1,0,1,0,0,0,0,0,1,0,0,0,0,
		1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,1,
		0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
		1,0,1,1,0,1,1,1,0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
		1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
		0,1,0,0,1,0,0,0,1,1,1,0,0,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
		1,0,1,1,0,1,1,1,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,1,0,1,1,1,0,0,1,
		0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
		1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
		1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,0,0,1,1};

static const u8 boolTable[32] = {0,0,1,1,0,0,1,0,0,1,1,0,1,1,0,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,0};

#endif