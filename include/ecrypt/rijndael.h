/*	$OpenBSD: rijndael.h,v 1.13 2008/06/09 07:49:45 djm Exp $ */

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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
