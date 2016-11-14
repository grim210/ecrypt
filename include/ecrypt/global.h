#ifndef ECRYPT_GLOBAL_H
#define ECRYPT_GLOBAL_H

#define ECRYPT_NO_ERROR			(0)
#define ECRYPT_UNTESTED			(1)
#define ECRYPT_INVALID_LENGTH		(2)
#define ECRYPT_NULL_PTR			(3)
#define ECRYPT_INVALID_PARAMETERS	(4)

#define AES_MAXKEYBITS			(256)
#define AES_MAXKEYBYTES			(AES_MAXKEYBITS/8)

/* For 256-bit keys, fewer rounds for smaller keys. */
#define AES_MAXROUNDS			(14)

#endif /* ECRYPT_GLOBAL_H */
