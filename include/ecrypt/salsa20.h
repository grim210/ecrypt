#ifndef ECRYPT_SALSA20_H
#define ECRYPT_SALSA20_H

struct salsa20_ctx_t {
};

int salsa20_end(struct salsa20_ctx_t* ctx);
int salsa20_init(struct salsa20_ctx_t* ctx, const uint8_t* key, size_t len);
int salsa20_decrypt(struct salsa20_ctx_t* ctx, const uint8_t* ct,
    size_t ct_len, uint8_t* out);
int salsa20_encrypt(struct salsa20_ctx_t* ctx, const uint8_t* pt,
    size_t pt_len, uint8_t* out);

#endif
