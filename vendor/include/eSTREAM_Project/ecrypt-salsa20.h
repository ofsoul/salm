/* ecrypt-sync.h */

/* 
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 * 
 * *** Please only edit parts marked with "[edit]". ***
 */

#ifndef __ECRYPT_SALSA20_H
#define __ECRYPT_SALSA20_H

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
 * The name of your cipher.
 */
#define SALSA20_ECRYPT_NAME "Salsa20 stream cipher"    /* [edit] */ 

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

#define SALSA20_ECRYPT_MAXKEYSIZE 256                 /* [edit] */
#define SALSA20_ECRYPT_KEYSIZE(i) (128 + (i)*128)     /* [edit] */

#define SALSA20_ECRYPT_MAXIVSIZE 64                   /* [edit] */
#define SALSA20_ECRYPT_IVSIZE(i) (64 + (i)*64)        /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
  u32 input[16]; /* could be compressed */
  /* 
   * [edit]
   *
   * Put here all state variable needed during the encryption process.
   */
} SALSA20_ECRYPT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void SALSA20_ECRYPT_init();

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void SALSA20_ECRYPT_keysetup(
  SALSA20_ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void SALSA20_ECRYPT_ivsetup(
  SALSA20_ECRYPT_ctx* ctx, 
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

void SALSA20_ECRYPT_encrypt_bytes(
  SALSA20_ECRYPT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void SALSA20_ECRYPT_decrypt_bytes(
  SALSA20_ECRYPT_ctx* ctx, 
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

#define SALSA20_ECRYPT_GENERATES_KEYSTREAM
#ifdef SALSA20_ECRYPT_GENERATES_KEYSTREAM

void SALSA20_ECRYPT_keystream_bytes(
  SALSA20_ECRYPT_ctx* ctx,
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
#define SALSA20_ECRYPT_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

void SALSA20_ECRYPT_encrypt_packet(
  SALSA20_ECRYPT_ctx* ctx, 
  const u8* iv,
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);

void SALSA20_ECRYPT_decrypt_packet(
  SALSA20_ECRYPT_ctx* ctx, 
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

#define SALSA20_ECRYPT_BLOCKLENGTH 64                  /* [edit] */

#define SALSA20_ECRYPT_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef SALSA20_ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define SALSA20_ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  SALSA20_ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * SALSA20_ECRYPT_BLOCKLENGTH)

#define SALSA20_ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  SALSA20_ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * SALSA20_ECRYPT_BLOCKLENGTH)

#ifdef SALSA20_ECRYPT_GENERATES_KEYSTREAM

#define SALSA20_ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
  SALSA20_ECRYPT_AE_keystream_bytes(ctx, keystream,                        \
    (blocks) * SALSA20_ECRYPT_BLOCKLENGTH)

#endif

#else

void SALSA20_ECRYPT_encrypt_blocks(
  SALSA20_ECRYPT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 blocks);                /* Message length in blocks. */ 

void SALSA20_ECRYPT_decrypt_blocks(
  SALSA20_ECRYPT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 blocks);                /* Message length in blocks. */ 

#ifdef SALSA20_ECRYPT_GENERATES_KEYSTREAM

void SALSA20_ECRYPT_keystream_blocks(
  SALSA20_ECRYPT_AE_ctx* ctx,
  const u8* keystream,
  u32 blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/* ------------------------------------------------------------------------- */

#endif //__ECRYPT_SALSA20_H
