#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>

/* pbkdf2_hmac_sha256
 *
 * description: takes the key, salt, number of rounds and size of the
 *     requested key and performs pbkdf2 key stretching to meet that
 *     requirement.
 *
 * inputs:
 *     key: this is the key the user provides.  typically in ASCII if the
 *         user is using an en_US keyboard.
 *     klen: length of the key the user provided.
 *     salt: this is used to strengthen the password.  This is also typically
 *         stored by the system using this library.  It is also recommended
 *         that the salt be unique per user.
 *     slen: length of the salt.  There is no upper limit.
 *     out: the buffer that the stretched key will be stored in.
 *     olen: the length of the out buffer in bytes.  This will be used to
 *         determine what length the stretched key will be.
 *     rounds: how many rounds of 'mixing' the algorithm will perform.
 * outpus:
 *     none.
 *****************************************************************************/
void pbkdf2_hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* salt,
    size_t slen, uint8_t* out, size_t olen, uint32_t rounds);

#endif
