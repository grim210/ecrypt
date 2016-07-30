/* This file is meant to act as a way to compare the results from this library
 * to the test vectors provided by Bruce Schnier's blog */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bfcrypt/bfcrypt.h>

const unsigned char ivc[8] = {
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

const unsigned char keyc[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87
};

/* This is a null-terminatd string. ASCII: "7654321 Now is the time for " */
const unsigned char def_data[29] = {
    0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
    0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
    0x66, 0x6F, 0x72, 0x20, 0x00
};

int test_cbc(void);
int test_ecb(void);

int main(int argc, char* argv[])
{
    fprintf(stdout, "********Integer Widths********\n");
    fprintf(stdout, "unsigned char is %u\n",
        (unsigned int)sizeof(unsigned char));
    fprintf(stdout, "unsigned short is %u\n",
        (unsigned int)sizeof(unsigned short));
    fprintf(stdout, "unsigned int is %u\n",
        (unsigned int)sizeof(unsigned int));
    fprintf(stdout, "unsigned long is %u\n",
        (unsigned int)sizeof(unsigned long));
    fprintf(stdout, "unsigned long long is %u\n",
        (unsigned int)sizeof(unsigned long long));

    fprintf(stdout, "********Simple ECB Test Vector********\n");
    test_ecb();

    fprintf(stdout, "********Simple CBC Test Vector********\n");
    test_cbc();
    
    return 0;
}

int test_ecb(void)
{
    int i;
    struct blowfish_context_t ctx;
    unsigned char key[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char pt[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char ct[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    blowfish_init(&ctx, key, 8);
    blowfish_encrypt_ecb(&ctx, pt, 8, ct);
    
    fprintf(stdout, "Key: ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", key[i]);
    }
    fprintf(stdout, "\nPT:  ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", pt[i]);
    }
    fprintf(stdout, "\nCT:  ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", ct[i]);
    }
    fprintf(stdout, "\n");
    blowfish_end(&ctx);

    memset(key, 0xFF, 8);
    memset(pt, 0xFF, 8);
    memset(ct, 0, 8);

    blowfish_init(&ctx, key, 8);
    blowfish_encrypt_ecb(&ctx, pt, 8, ct);

    fprintf(stdout, "Key: ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", key[i]);
    }
    fprintf(stdout, "\nPT:  ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", pt[i]);
    }
    fprintf(stdout, "\nCT:  ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", ct[i]);
    }
    fprintf(stdout, "\n");
    blowfish_end(&ctx);

    return 0;
}

int test_cbc(void)
{
    int i;
    unsigned char iv[8];
    unsigned char key[16];
    unsigned char ct_buff[32];
    unsigned char pt_buff[32];
    struct blowfish_context_t ctx;

    memset(ct_buff, 0, 32);
    memset(pt_buff, 0, 32);

    memcpy(iv, ivc, 8);
    memcpy(key, keyc, 16);

    fprintf(stdout, "Init Vector: ");
    for (i = 0; i < 8; i++) {
        fprintf(stdout, "%02X", iv[i]);
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "Key:         ");
    for (i = 0; i < 16; ++i) {
        fprintf(stdout, "%02X", keyc[i]);
    }
    fprintf(stdout, "\n");

    memcpy(pt_buff, def_data, 29);

    blowfish_init(&ctx, key, 16);

    fprintf(stdout, "Plaintext:   ");
    for (i = 0; i < 32; ++i) {
        fprintf(stdout, "%02X", pt_buff[i]);
    }
    fprintf(stdout, "\n");

    blowfish_encrypt(&ctx, iv, pt_buff, 32, ct_buff);
    blowfish_end(&ctx);

    fprintf(stdout, "Encrypted:   ");
    for (i = 0; i < 32; ++i) {
        fprintf(stdout, "%02X", ct_buff[i]);
    }
    fprintf(stdout, "\n");

    /* erase the plaintext buffer */
    memset(pt_buff, 0, 32);

    /* just to make sure we're not pulling voodoo magic, rebuild a Blowfish
     * context with the same key. */
    blowfish_init(&ctx, key, 16);
    blowfish_decrypt(&ctx, iv, ct_buff, 32, pt_buff);

    fprintf(stdout, "Decrypted:   ");
    for (i = 0; i < 32; ++i) {
        fprintf(stdout, "%02X", pt_buff[i]);
    }
    fprintf(stdout, "\n");

    blowfish_end(&ctx);
    
    return 0;
}
