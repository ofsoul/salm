/* 
* Header file for synchronous stream ciphers without authentication
* mechanism.
* 
* *** Please only edit parts marked with "[edit]". ***
*/

#ifndef ECRYPT_SYNC
#define ECRYPT_SYNC

#include "ecrypt-portable.h"

#define SOSEMANUK_ECRYPT

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
* The name of your cipher.
*/
#define SOSEMANUK_ECRYPT_NAME "SOSEMANUK"    /* [edit] */ 

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

#define SOSEMANUK_ECRYPT_MAXKEYSIZE 256                 /* [edit] */
#define SOSEMANUK_ECRYPT_KEYSIZE(i) (8 + (i)*8)         /* [edit] */

#define SOSEMANUK_ECRYPT_MAXIVSIZE 128                  /* [edit] */
#define SOSEMANUK_ECRYPT_IVSIZE(i) (8 + (i)*8)          /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
* ECRYPT_ctx is the structure containing the representation of the
* internal state of your cipher. 
*/

typedef struct
{
	/* 
	* [edit]
	*
	* Put here all state variable needed during the encryption process.
	*/

	/*
	* Sub-keys (computed from the key).
	*/
	u32 sk[100];

	/*
	* IV length (in bytes).
	*/
	size_t ivlen;

	/*
	* Internal state.
	*/
	u32 s00, s01, s02, s03, s04, s05, s06, s07, s08, s09;
	u32 r1, r2;

} SOSEMANUK_ECRYPT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
* Key and message independent initialization. This function will be
* called once when the program starts (e.g., to build expanded S-box
* tables).
*/
void SOSEMANUK_ECRYPT_init(void);

/*
* Key setup. It is the user's responsibility to select the values of
* keysize and ivsize from the set of supported values specified
* above.
*/
void SOSEMANUK_ECRYPT_keysetup(
					 SOSEMANUK_ECRYPT_ctx* ctx, 
					 const u8* key, 
					 u32 keysize,                /* Key size in bits. */ 
					 u32 ivsize);                /* IV size in bits. */ 

/*
* IV setup. After having called ECRYPT_keysetup(), the user is
* allowed to call ECRYPT_ivsetup() different times in order to
* encrypt/decrypt different messages with the same key but different
* IV's.
*/
void SOSEMANUK_ECRYPT_ivsetup(
					SOSEMANUK_ECRYPT_ctx* ctx, 
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

/*
* By default ECRYPT_encrypt_bytes() and ECRYPT_decrypt_bytes() are
* defined as macros which redirect the call to a single function
* ECRYPT_process_bytes(). If you want to provide separate encryption
* and decryption functions, please undef
* ECRYPT_HAS_SINGLE_BYTE_FUNCTION.
*/
#define SOSEMANUK_ECRYPT_HAS_SINGLE_BYTE_FUNCTION       /* [edit] */
#ifdef SOSEMANUK_ECRYPT_HAS_SINGLE_BYTE_FUNCTION

#define SOSEMANUK_ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext, msglen)   \
	SOSEMANUK_ECRYPT_process_bytes(0, ctx, plaintext, ciphertext, msglen)

#define SOSEMANUK_ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext, msglen)   \
	SOSEMANUK_ECRYPT_process_bytes(1, ctx, ciphertext, plaintext, msglen)

void SOSEMANUK_ECRYPT_process_bytes(
						  int action,                 /* 0 = encrypt; 1 = decrypt; */
						  SOSEMANUK_ECRYPT_ctx* ctx, 
						  const u8* input, 
						  u8* output, 
						  u32 msglen);                /* Message length in bytes. */ 

#else

void SOSEMANUK_ECRYPT_encrypt_bytes(
						  SOSEMANUK_ECRYPT_ctx* ctx, 
						  const u8* plaintext, 
						  u8* ciphertext, 
						  u32 msglen);                /* Message length in bytes. */ 

void SOSEMANUK_ECRYPT_decrypt_bytes(
						  SOSEMANUK_ECRYPT_ctx* ctx, 
						  const u8* ciphertext, 
						  u8* plaintext, 
						  u32 msglen);                /* Message length in bytes. */ 

#endif

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
* For testing purposes it can sometimes be useful to have a function
* which immediately generates keystream without having to provide it
* with a zero plaintext. If your cipher cannot provide this function
* (e.g., because it is not strictly a synchronous cipher), please
* reset the ECRYPT_GENERATES_KEYSTREAM flag.
*/

#define SOSEMANUK_ECRYPT_GENERATES_KEYSTREAM
#ifdef SOSEMANUK_ECRYPT_GENERATES_KEYSTREAM

void SOSEMANUK_ECRYPT_keystream_bytes(
							SOSEMANUK_ECRYPT_ctx* ctx,
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
#define SOSEMANUK_ECRYPT_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

/*
* Undef ECRYPT_HAS_SINGLE_PACKET_FUNCTION if you want to provide
* separate packet encryption and decryption functions.
*/
#define SOSEMANUK_ECRYPT_HAS_SINGLE_PACKET_FUNCTION     /* [edit] */
#ifdef SOSEMANUK_ECRYPT_HAS_SINGLE_PACKET_FUNCTION

#define SOSEMANUK_ECRYPT_encrypt_packet(                                        \
	ctx, iv, plaintext, ciphertext, mglen)                            \
	SOSEMANUK_ECRYPT_process_packet(0,                                            \
	ctx, iv, plaintext, ciphertext, mglen)

#define SOSEMANUK_ECRYPT_decrypt_packet(                                        \
	ctx, iv, ciphertext, plaintext, mglen)                            \
	SOSEMANUK_ECRYPT_process_packet(1,                                            \
	ctx, iv, ciphertext, plaintext, mglen)

void SOSEMANUK_ECRYPT_process_packet(
						   int action,                 /* 0 = encrypt; 1 = decrypt; */
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* iv,
						   const u8* input, 
						   u8* output, 
						   u32 msglen);

#else

void SOSEMANUK_ECRYPT_encrypt_packet(
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* iv,
						   const u8* plaintext, 
						   u8* ciphertext, 
						   u32 msglen);

void SOSEMANUK_ECRYPT_decrypt_packet(
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* iv,
						   const u8* ciphertext, 
						   u8* plaintext, 
						   u32 msglen);

#endif

/*
* Encryption/decryption of blocks.
* 
* By default, these functions are defined as macros. If you want to
* provide a different implementation, please undef the
* ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
* declared below.
*/

#define SOSEMANUK_ECRYPT_BLOCKLENGTH 80                /* [edit] */

#undef SOSEMANUK_ECRYPT_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef SOSEMANUK_ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define SOSEMANUK_ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
	SOSEMANUK_ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
	(blocks) * SOSEMANUK_ECRYPT_BLOCKLENGTH)

#define SOSEMANUK_ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
	SOSEMANUK_ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
	(blocks) * SOSEMANUK_ECRYPT_BLOCKLENGTH)

#ifdef SOSEMANUK_ECRYPT_GENERATES_KEYSTREAM

#define SOSEMANUK_ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
	SOSEMANUK_ECRYPT_keystream_bytes(ctx, keystream,                           \
	(blocks) * SOSEMANUK_ECRYPT_BLOCKLENGTH)

#endif

#else

/*
* Undef ECRYPT_HAS_SINGLE_BLOCK_FUNCTION if you want to provide
* separate block encryption and decryption functions.
*/
#define SOSEMANUK_ECRYPT_HAS_SINGLE_BLOCK_FUNCTION      /* [edit] */
#ifdef SOSEMANUK_ECRYPT_HAS_SINGLE_BLOCK_FUNCTION

#define SOSEMANUK_ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)     \
	SOSEMANUK_ECRYPT_process_blocks(0, ctx, plaintext, ciphertext, blocks)

#define SOSEMANUK_ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)     \
	SOSEMANUK_ECRYPT_process_blocks(1, ctx, ciphertext, plaintext, blocks)

void SOSEMANUK_ECRYPT_process_blocks(
						   int action,                 /* 0 = encrypt; 1 = decrypt; */
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* input, 
						   u8* output, 
						   u32 blocks);                /* Message length in blocks. */

#else

void SOSEMANUK_ECRYPT_encrypt_blocks(
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* plaintext, 
						   u8* ciphertext, 
						   u32 blocks);                /* Message length in blocks. */ 

void SOSEMANUK_ECRYPT_decrypt_blocks(
						   SOSEMANUK_ECRYPT_ctx* ctx, 
						   const u8* ciphertext, 
						   u8* plaintext, 
						   u32 blocks);                /* Message length in blocks. */ 

#endif

#ifdef SOSEMANUK_ECRYPT_GENERATES_KEYSTREAM

void SOSEMANUK_ECRYPT_keystream_blocks(
							 SOSEMANUK_ECRYPT_ctx* ctx,
							 u8* keystream,
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
#define SOSEMANUK_ECRYPT_MAXVARIANT 1                   /* [edit] */

#ifndef SOSEMANUK_ECRYPT_VARIANT
#define SOSEMANUK_ECRYPT_VARIANT 1
#endif

#if (SOSEMANUK_ECRYPT_VARIANT > SOSEMANUK_ECRYPT_MAXVARIANT)
#error this variant does not exist
#endif

/* ------------------------------------------------------------------------- */

#endif