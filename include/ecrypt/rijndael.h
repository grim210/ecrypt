#ifndef ECRYPT_RIJNDAEL_H
#define ECRYPT_RIJNDAEL_H

#include <stdint.h>
#include "global.h"

/*  The structure for key information */
typedef struct {
	int enc_only;	/* context contains only encrypt schedule */
	int Nr;		/* key-length-dependent number of rounds */
	uint32_t ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	uint32_t dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

int rijndael_set_key(rijndael_ctx *, const uint8_t *, int);
int rijndael_set_key_enc_only(rijndael_ctx *, const uint8_t *, int);
void rijndael_decrypt(rijndael_ctx *, const uint8_t *, uint8_t *);
void rijndael_encrypt(rijndael_ctx *, const uint8_t *, uint8_t *);

int rijndaelKeySetupEnc(uint32_t *, const uint8_t *, int);
int rijndaelKeySetupDec(uint32_t *, const uint8_t *, int);
void rijndaelEncrypt(const uint32_t *, int, const uint8_t *, uint8_t *);

#endif /* ECRYPT_RIJNDAEL_H */
