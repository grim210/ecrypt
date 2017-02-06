#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ecrypt/kdf.h>

/* for those magic SHA256 numbers.. */
#define SHA256_BLOCK_SIZE       (64)
#define SHA256_DIGEST_LENGTH    (32)

/* SHA256 rotate macros */
#define SHA256_ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define SHA256_ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))

/* from the name, one assumes that this adds a 32-bit int to a 64-bit int,
 * but if you had to decipher the code, that wouldn't be all that clear */
#define SHA256_INT64_ADD32(a,b,c) if (a > 0xffffffff - (c)) ++b; a+=c;

/* basic SHA256 functions.  defined in the standard */
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

struct sha256_context_t {
    uint32_t datalen;
    uint32_t state[8];
    uint32_t bitlen[2];
    uint8_t data[64];
};

/* used to initialize the state for sha256 */
const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* function prototypes */
void sha256_finalize(struct sha256_context_t* ctx, uint8_t* hash);
void sha256_init(struct sha256_context_t* ctx);
void sha256_transform(struct sha256_context_t* ctx, uint8_t* data);
void sha256_update(struct sha256_context_t* ctx, const uint8_t* data,
    size_t len);
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* message,
    size_t mlen, uint8_t* out);

/* function definitions */

/* inspired by 'pkcs5_pbkdf2.c' of the OpenBSD project. */
int pbkdf2_hmac_sha256(const uint8_t* pass, size_t plen, const uint8_t* salt,
    size_t slen, uint8_t* out, size_t olen, uint32_t rounds)
{
    uint8_t* asalt;
    uint8_t obuf[SHA256_DIGEST_LENGTH];
    uint8_t d1[SHA256_DIGEST_LENGTH];
    uint8_t d2[SHA256_DIGEST_LENGTH];

    int i, j, count;

    /* I need ERROR CODES!! */
    if (rounds < 1 || olen == 0 || slen == 0) {
        return ECRYPT_INVALID_PARAMETERS;
    }

    /* I really don't want to touch the heap.  I may put an upper limit to the
     * salt, just so I can have asalt allocated on the stack.  Is something
     * like 1024 bytes reasonable for salt length? */
    asalt = (uint8_t*)malloc(sizeof(uint8_t) * (slen + 4));
    memset(asalt, 0, slen + 4);
    memcpy(asalt, salt, slen);

    for (count = 1; olen > 0; ++count) {
        /* append 'count' to salt in big-endian format */
        asalt[slen + 0] = (count >> 24) & 0xff;
        asalt[slen + 1] = (count >> 16) & 0xff;
        asalt[slen + 2] = (count >> 8) & 0xff;
        asalt[slen + 3] = count & 0xff;

        /* this is the step that is different than the rest */
        hmac_sha256(pass, plen, asalt, slen + 4, d1);
        memcpy(obuf, d1, SHA256_DIGEST_LENGTH);

        for (i = 1; i < rounds; ++i) {
            hmac_sha256(pass, plen, d1, SHA256_DIGEST_LENGTH, d2);
            memcpy(d1, d2, SHA256_DIGEST_LENGTH);
            for (j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
                obuf[j] ^= d1[j];
            }
        }

        if (olen < SHA256_DIGEST_LENGTH) {
            memcpy(out, obuf, olen);
            out += olen;
            olen = 0;
        } else {
            memcpy(out, obuf, SHA256_DIGEST_LENGTH);
            out += SHA256_DIGEST_LENGTH;
            olen -= SHA256_DIGEST_LENGTH;
        }
    }

    memset(asalt, 0, slen + 4);
    memset(d1, 0, SHA256_DIGEST_LENGTH);
    memset(d2, 0, SHA256_DIGEST_LENGTH);
    memset(obuf, 0, SHA256_DIGEST_LENGTH);

    free(asalt);

    return ECRYPT_NO_ERROR;
}

void sha256_finalize(struct sha256_context_t* ctx, uint8_t* hash)
{
    uint32_t i;

    i  = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }

        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    SHA256_INT64_ADD32(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen*8);
    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;

    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;

    sha256_transform(ctx, ctx->data);

    /* reverse byte ordering.. */
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - (i*8))) & 0x000000ff;
        hash[i+4] = (ctx->state[1] >> (24 - (i*8))) & 0x000000ff;
        hash[i+8] = (ctx->state[2] >> (24 - (i*8))) & 0x000000ff;
        hash[i+12] = (ctx->state[3] >> (24 - (i*8))) & 0x000000ff;
        hash[i+16] = (ctx->state[4] >> (24 - (i*8))) & 0x000000ff;
        hash[i+20] = (ctx->state[5] >> (24 - (i*8))) & 0x000000ff;
        hash[i+24] = (ctx->state[6] >> (24 - (i*8))) & 0x000000ff;
        hash[i+28] = (ctx->state[7] >> (24 - (i*8))) & 0x000000ff;
    }
}

void sha256_init(struct sha256_context_t* ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;

    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_transform(struct sha256_context_t* ctx, uint8_t* data)
{
    uint32_t a, b, c, d, e, f, g, h, i, j;
    uint32_t t1, t2;
    uint32_t m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j+0] << 24) | (data[j+1] << 16) |
               (data[j+2] <<  8) | (data[j+3] << 0);
    }

    while (i < 64) {
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];
        ++i;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_k[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_update(struct sha256_context_t* ctx, const uint8_t* data,
    size_t len)
{
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            SHA256_INT64_ADD32(ctx->bitlen[0], ctx->bitlen[1], 512);
            ctx->datalen = 0;
        }
    }
}

/* cannot handle keys larger than 128 bytes.  Which is weird.  That is an
 * hmac-ism, or something I made up for this?  I should comment better... */
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* message,
    size_t mlen, uint8_t* out)
{
    int i;
    struct sha256_context_t ctx;
    uint8_t houtput[32];

    if (klen > 128) {
        return;
    }

    uint8_t k_opad[64];
    uint8_t k_ipad[64];

    /* zero those two arrays. */
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);

    if (klen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, klen);
        sha256_finalize(&ctx, houtput);

        memset(&ctx, 0, sizeof(struct sha256_context_t));

        memcpy(k_ipad, houtput, 32);
        memcpy(k_opad, houtput, 32);
    } else {
        memcpy(k_ipad, key, klen);
        memcpy(k_opad, key, klen);
    }

    for (i = 0; i < 64; ++i) {
        k_ipad[i] = k_ipad[i] ^ 0x36;
        k_opad[i] = k_opad[i] ^ 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, message, mlen);
    sha256_finalize(&ctx, out);
    memset(&ctx, 0, sizeof(struct sha256_context_t));
    
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, out, 32);
    sha256_finalize(&ctx, out);
    memset(&ctx, 0, sizeof(struct sha256_context_t));

    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memset(houtput, 0, 32);
}
