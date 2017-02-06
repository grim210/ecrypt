#include <ecrypt/rijndael.h>
#include "rijndael_const.c"

#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16)\
	^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))

#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24);\
	(ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8);\
	(ct)[3] = (uint8_t)(st); }

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
int
rijndaelKeySetupEnc(uint32_t *rk, const uint8_t *cipherKey, int keyBits)
{
   	int i = 0;
	uint32_t temp;

	rk[0] = GETU32(cipherKey     );
	rk[1] = GETU32(cipherKey +  4);
	rk[2] = GETU32(cipherKey +  8);
	rk[3] = GETU32(cipherKey + 12);
	if (keyBits == 128) {
		while (1) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			if (++i == 10) {
				return 10;
			}
			rk += 4;
		}
	}
	rk[4] = GETU32(cipherKey + 16);
	rk[5] = GETU32(cipherKey + 20);
	if (keyBits == 192) {
		while (1) {
			temp = rk[ 5];
			rk[ 6] = rk[ 0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[ 7] = rk[ 1] ^ rk[ 6];
			rk[ 8] = rk[ 2] ^ rk[ 7];
			rk[ 9] = rk[ 3] ^ rk[ 8];
			if (++i == 8) {
				return 12;
			}
			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];
			rk += 6;
		}
	}
	rk[6] = GETU32(cipherKey + 24);
	rk[7] = GETU32(cipherKey + 28);
	if (keyBits == 256) {
		while (1) {
			temp = rk[ 7];
			rk[ 8] = rk[ 0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[ 9] = rk[ 1] ^ rk[ 8];
			rk[10] = rk[ 2] ^ rk[ 9];
			rk[11] = rk[ 3] ^ rk[10];
			if (++i == 7) {
				return 14;
			}
			temp = rk[11];
			rk[12] = rk[ 4] ^
				(Te2[(temp >> 24)       ] & 0xff000000) ^
				(Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
				(Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
				(Te1[(temp      ) & 0xff] & 0x000000ff);
			rk[13] = rk[ 5] ^ rk[12];
			rk[14] = rk[ 6] ^ rk[13];
		     	rk[15] = rk[ 7] ^ rk[14];
			rk += 8;
		}
	}
	return 0;
}

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
int
rijndaelKeySetupDec(uint32_t *rk, const uint8_t *cipherKey, int keyBits)
{
    int Nr, i, j;
    uint32_t temp;

    /* Expand the cipher key: */
    Nr = rijndaelKeySetupEnc(rk, cipherKey, keyBits);

    /* Invert the order of the round keys: */
    for (i = 0, j = 4*Nr; i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }

    /*
    * Apply the inverse MixColumn transform to all round keys except
    * the first and the last:
    */
    for (i = 1; i < Nr; i++) {
        rk += 4;
        rk[0] =
            Td0[Te1[(rk[0] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[0] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[0] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[0]      ) & 0xff] & 0xff];
        rk[1] =
            Td0[Te1[(rk[1] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[1] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[1] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[1]      ) & 0xff] & 0xff];
        rk[2] =
            Td0[Te1[(rk[2] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[2] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[2] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[2]      ) & 0xff] & 0xff];
        rk[3] =
            Td0[Te1[(rk[3] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[3] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[3] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[3]      ) & 0xff] & 0xff];
    }

    return Nr;
}

/*
* XXX: This is a disaster.  Defining the length of the array in the
* function definition is not a standard C mechanism.  Not sure why this
* code is in OpenBSD like this.
*/
void
rijndaelEncrypt(const uint32_t *rk, int Nr, const uint8_t pt[16],
    uint8_t ct[16])
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
	int r;

	/*
	* Map byte array block to cipher state
	* and add initial round key:
	*/
	s0 = GETU32(pt     ) ^ rk[0];
	s1 = GETU32(pt +  4) ^ rk[1];
	s2 = GETU32(pt +  8) ^ rk[2];
	s3 = GETU32(pt + 12) ^ rk[3];

	r = Nr >> 1;
	while (1) {
		t0 =
		    Te0[(s0 >> 24)       ] ^
		    Te1[(s1 >> 16) & 0xff] ^
		    Te2[(s2 >>  8) & 0xff] ^
		    Te3[(s3      ) & 0xff] ^
		    rk[4];
		t1 =
		    Te0[(s1 >> 24)       ] ^
		    Te1[(s2 >> 16) & 0xff] ^
		    Te2[(s3 >>  8) & 0xff] ^
		    Te3[(s0      ) & 0xff] ^
		    rk[5];
		t2 =
		    Te0[(s2 >> 24)       ] ^
		    Te1[(s3 >> 16) & 0xff] ^
		    Te2[(s0 >>  8) & 0xff] ^
		    Te3[(s1      ) & 0xff] ^
		    rk[6];
		t3 =
		    Te0[(s3 >> 24)       ] ^
		    Te1[(s0 >> 16) & 0xff] ^
		    Te2[(s1 >>  8) & 0xff] ^
		    Te3[(s2      ) & 0xff] ^
		    rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
		    Te0[(t0 >> 24)       ] ^
		    Te1[(t1 >> 16) & 0xff] ^
		    Te2[(t2 >>  8) & 0xff] ^
		    Te3[(t3      ) & 0xff] ^
		    rk[0];
		s1 =
		    Te0[(t1 >> 24)       ] ^
		    Te1[(t2 >> 16) & 0xff] ^
		    Te2[(t3 >>  8) & 0xff] ^
		    Te3[(t0      ) & 0xff] ^
		    rk[1];
		s2 =
		    Te0[(t2 >> 24)       ] ^
		    Te1[(t3 >> 16) & 0xff] ^
		    Te2[(t0 >>  8) & 0xff] ^
		    Te3[(t1      ) & 0xff] ^
		    rk[2];
		s3 =
		    Te0[(t3 >> 24)       ] ^
		    Te1[(t0 >> 16) & 0xff] ^
		    Te2[(t1 >>  8) & 0xff] ^
		    Te3[(t2      ) & 0xff] ^
		    rk[3];
	}

	/*
	* Apply last round and map cipher state to byte array block:
	*/
	s0 =
		(Te2[(t0 >> 24)       ] & 0xff000000) ^
		(Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t3      ) & 0xff] & 0x000000ff) ^
		rk[0];
	PUTU32(ct     , s0);

	s1 =
		(Te2[(t1 >> 24)       ] & 0xff000000) ^
		(Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t0      ) & 0xff] & 0x000000ff) ^
		rk[1];
	PUTU32(ct +  4, s1);

	s2 =
		(Te2[(t2 >> 24)       ] & 0xff000000) ^
		(Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t1      ) & 0xff] & 0x000000ff) ^
		rk[2];
	PUTU32(ct +  8, s2);

	s3 =
		(Te2[(t3 >> 24)       ] & 0xff000000) ^
		(Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t2      ) & 0xff] & 0x000000ff) ^
		rk[3];
	PUTU32(ct + 12, s3);
}

static void
rijndaelDecrypt(const uint32_t *rk, int Nr, const uint8_t ct[16],
    uint8_t pt[16])
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
	int r;

	/*
	* Map byte array block to cipher state and add initial round key:
	*/
	s0 = GETU32(ct     ) ^ rk[0];
	s1 = GETU32(ct +  4) ^ rk[1];
	s2 = GETU32(ct +  8) ^ rk[2];
	s3 = GETU32(ct + 12) ^ rk[3];

	/* Nr - 1 full rounds: */
	r = Nr >> 1;
	while (1) {
		t0 =
		    Td0[(s0 >> 24)       ] ^
		    Td1[(s3 >> 16) & 0xff] ^
		    Td2[(s2 >>  8) & 0xff] ^
		    Td3[(s1      ) & 0xff] ^
		    rk[4];
		t1 =
		    Td0[(s1 >> 24)       ] ^
		    Td1[(s0 >> 16) & 0xff] ^
		    Td2[(s3 >>  8) & 0xff] ^
		    Td3[(s2      ) & 0xff] ^
		    rk[5];
		t2 =
		    Td0[(s2 >> 24)       ] ^
		    Td1[(s1 >> 16) & 0xff] ^
		    Td2[(s0 >>  8) & 0xff] ^
		    Td3[(s3      ) & 0xff] ^
		    rk[6];
		t3 =
		    Td0[(s3 >> 24)       ] ^
		    Td1[(s2 >> 16) & 0xff] ^
		    Td2[(s1 >>  8) & 0xff] ^
		    Td3[(s0      ) & 0xff] ^
		    rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
		    Td0[(t0 >> 24)       ] ^
		    Td1[(t3 >> 16) & 0xff] ^
		    Td2[(t2 >>  8) & 0xff] ^
		    Td3[(t1      ) & 0xff] ^
		    rk[0];
		s1 =
		    Td0[(t1 >> 24)       ] ^
		    Td1[(t0 >> 16) & 0xff] ^
		    Td2[(t3 >>  8) & 0xff] ^
		    Td3[(t2      ) & 0xff] ^
		    rk[1];
		s2 =
		    Td0[(t2 >> 24)       ] ^
		    Td1[(t1 >> 16) & 0xff] ^
		    Td2[(t0 >>  8) & 0xff] ^
		    Td3[(t3      ) & 0xff] ^
		    rk[2];
		s3 =
		    Td0[(t3 >> 24)       ] ^
		    Td1[(t2 >> 16) & 0xff] ^
		    Td2[(t1 >>  8) & 0xff] ^
		    Td3[(t0      ) & 0xff] ^
		    rk[3];
	}

	/*
	* Apply last round and map cipher state to byte array block:
	*/
   	s0 =
   		(Td4[(t0 >> 24)       ] << 24) ^
   		(Td4[(t3 >> 16) & 0xff] << 16) ^
   		(Td4[(t2 >>  8) & 0xff] <<  8) ^
   		(Td4[(t1      ) & 0xff])       ^
   		rk[0];
	PUTU32(pt     , s0);

   	s1 =
   		(Td4[(t1 >> 24)       ] << 24) ^
   		(Td4[(t0 >> 16) & 0xff] << 16) ^
   		(Td4[(t3 >>  8) & 0xff] <<  8) ^
   		(Td4[(t2      ) & 0xff])       ^
   		rk[1];
	PUTU32(pt +  4, s1);

   	s2 =
   		(Td4[(t2 >> 24)       ] << 24) ^
   		(Td4[(t1 >> 16) & 0xff] << 16) ^
   		(Td4[(t0 >>  8) & 0xff] <<  8) ^
   		(Td4[(t3      ) & 0xff])       ^
   		rk[2];
	PUTU32(pt +  8, s2);

   	s3 =
   		(Td4[(t3 >> 24)       ] << 24) ^
   		(Td4[(t2 >> 16) & 0xff] << 16) ^
   		(Td4[(t1 >>  8) & 0xff] <<  8) ^
   		(Td4[(t0      ) & 0xff])       ^
   		rk[3];
	PUTU32(pt + 12, s3);
}

/* setup key context for encryption only */
int
rijndael_set_key_enc_only(rijndael_ctx *ctx, const uint8_t *key, int bits)
{
	int rounds;

	rounds = rijndaelKeySetupEnc(ctx->ek, key, bits);
	if (rounds == 0)
		return -1;

	ctx->Nr = rounds;
	ctx->enc_only = 1;

	return 0;
}

/* setup key context for both encryption and decryption */
int
rijndael_set_key(rijndael_ctx *ctx, const uint8_t *key, int bits)
{
	int rounds;

	rounds = rijndaelKeySetupEnc(ctx->ek, key, bits);
	if (rounds == 0)
		return -1;
	if (rijndaelKeySetupDec(ctx->dk, key, bits) != rounds)
		return -1;

	ctx->Nr = rounds;
	ctx->enc_only = 0;

	return 0;
}

void
rijndael_decrypt(rijndael_ctx *ctx, const uint8_t *src, uint8_t *dst)
{
	rijndaelDecrypt(ctx->dk, ctx->Nr, src, dst);
}

void
rijndael_encrypt(rijndael_ctx *ctx, const uint8_t *src, uint8_t *dst)
{
	rijndaelEncrypt(ctx->ek, ctx->Nr, src, dst);
}
