#ifndef ECRYPT_BLOWFISH_H
#define ECRYPT_BLOWFISH_H

/* fixed width types are a must in this context */
#include <stdint.h>
#include <stdlib.h>

#include "global.h"

#define BLOWFISH_P_LENGTH		(18)
#define BLOWFISH_S_LENGTH		(1024)

struct blowfish_context_t {
	uint32_t P[BLOWFISH_P_LENGTH];
	uint32_t S[BLOWFISH_S_LENGTH];
};

/* blowfish_end:
 *
 * description:
 *     Takes the provided context and clears all the memory and frees the
 *     data allocated by the bf_init function.
 *
 * inputs:
 *     context: a context that has been initialized with blowfish_init.
 *
 * outputs:
 *     int: Error code.  If everything went well, it returns BF_NO_ERROR.
 *****************************************************************************/
int blowfish_end(struct blowfish_context_t* context);

/* blowfish_init:
 *
 * description:
 *     Takes the provided key and runs it through the blowfish key schedule
 *     in order to provide a blowfish context suitable for use in this library.
 *
 * inputs:
 *     ctx: a pre-allocated context.  In the calling code, this could be as
 *         simple as allocating on the stack and passing a reference.
 *     key: This is a raw key.  It's not hashed or anything by this function.
 *         If you provide a weak key (ie: a passphrase) expect poor security.
 *     klen: The length of the provided key.  Must be between 4 and 56 bytes.
 *
 * output:
 *     int: Error codes, suitable for comparing to the error definitions at
 *         the top of this header file.
 *****************************************************************************/
int blowfish_init(struct blowfish_context_t* ctx, const uint8_t* key,
    uint32_t klen);

/* blowfish_decrypt:
 *
 * description:
 *     Takes the initialization vector and the ciphertext and decrypts it using
 *     Chain-Block-Cipher mode of decryption.
 *
 * inputs:
 *     context: a context created from the bf_init function.
 *     iv: the initialization vector; necessary for CBC. 8 bytes in length.
 *     ct: the buffer of ciphertext.  should be padded to 64-bit alignment.
 *     ct_len: the length of the ct buffer; ct_len % 8 == 0 is tested.
 *     out: the buffer where the decypted data is stored.  should be identical
 *         in length to the ct buffer.
 *
 * outputs:
 *     int: error code.  If everything went well, should return BF_NO_ERROR
 *****************************************************************************/
int blowfish_decrypt(struct blowfish_context_t* context, const uint8_t* iv, 
    const uint8_t* ct, uint32_t ct_len, uint8_t* out);

/* blowfish_encrypt:
 *
 * decription:
 *     Takes the initialization vector and the plaintext and encrypts it using
 *     Chain-Block-Cipher mode of encryption.
 *
 * inputs:
 *     context: a context created from the bf_init function.
 *     iv: the initialization vector; necessary for CBC
 *     pt: the buffer of plaintext to be encrypted; should be properly padded
 *     pt_len: length of the pt buffer; pt_len % 8 == 0 is verified
 *     out: the buffer where the decrypted data is stored.  should be identical
 *         in length to the pt buffer.
 *
 * outputs:
 *     int: error code.  If everything went well, should return BF_NO_ERROR
 *****************************************************************************/
int blowfish_encrypt(struct blowfish_context_t* context, const uint8_t* iv,
    const uint8_t* pt, uint32_t pt_len, uint8_t* out);

/* blowfish_decrypt_ecb:
 *
 * decription:
 *     Decrypts, using ECB, the ct buffer.  Not recommended for common usage;
 *         use the blowfish_decrypt and blowfish_encrypt methods instead.
 *
 * inputs:
 *     context: a context created from the bf_init function.
 *     ct: the buffer of ciphertext to be encrypted; should be properly padded
 *     ct_len: length of the ct buffer; pt_len % 8 == 0 is verified
 *     out: the buffer where the decrypted data is stored.  should be identical
 *         in length to the pt buffer.
 *
 * outputs:
 *     int: error code.  If everything went well, should return BF_NO_ERROR
 *****************************************************************************/
int blowfish_decrypt_ecb(struct blowfish_context_t* context, const uint8_t* ct,
    uint32_t ct_len, uint8_t* out);

/* blowfish_encrypt_ecb:
 *
 * decription:
 *     Encrypts, using ECB, the pt buffer.  Not recommended for common usage;
 *         use the blowfish_encrypt and blowfish_decrypt methods instead.
 *
 * inputs:
 *     context: a context created from the bf_init function.
 *     pt: the buffer of plaintext to be encrypted; should be properly padded
 *     pt_len: length of the pt buffer; pt_len % 8 == 0 is verified
 *     out: the buffer where the decrypted data is stored.  should be identical
 *         in length to the pt buffer.
 *
 * outputs:
 *     int: error code.  If everything went well, should return BF_NO_ERROR
 *****************************************************************************/
int blowfish_encrypt_ecb(struct blowfish_context_t* context, const uint8_t* pt,
  uint32_t pt_len, uint8_t* out);

#endif /* ECRYPT_BLOWFISH_H */
