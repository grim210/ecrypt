#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bfcrypt/bfcrypt.h>

#define DEFAULT_PASS    ("password")
#define DEFAULT_SALT    ("salt")
#define DEFAULT_ROUNDS  (4096)
#define DEFAULT_LENGTH  (256)

int main(int argc, char* argv[])
{
    int i;
    uint8_t* output;
    int len = DEFAULT_LENGTH;
    const uint8_t* pass = (uint8_t*)DEFAULT_PASS;
    const uint8_t* salt = (uint8_t*)DEFAULT_SALT;
    uint32_t c = DEFAULT_ROUNDS;

    if (argc == 1) {
        fprintf(stdout, "Usage:\n\t-p\tPassword\n\t-s\tSalt\n\t-r\tRounds\n");
        fprintf(stdout, "\t-l\tKey Length\n\n");
        fprintf(stdout, "Using defaults!\n");
        fprintf(stdout, "pass: %s\n", pass);
        fprintf(stdout, "salt: %s\n", salt);
        fprintf(stdout, "rounds: %d\n", c);
        fprintf(stdout, "length: %d bits\n", len);
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0) {
            fprintf(stdout, "Setting password to %s\n", argv[i+1]);
            pass = (uint8_t*)argv[i+1];
            i++;
            continue;
        }

        if (strcmp(argv[i], "-s") == 0) {
            fprintf(stdout, "Setting salt to %s\n", argv[i+1]);
            salt = (uint8_t*)argv[i+1];
            i++;
            continue;
        }

        if (strcmp(argv[i], "-r") == 0) {
            fprintf(stdout, "Setting rounds to %s\n", argv[i+1]);
            c = (uint32_t)atoi(argv[i+1]);
            i++;
            continue;
        }

        if (strcmp(argv[i], "-l") == 0) {
            fprintf(stdout, "Setting length to %s\n", argv[i+1]);
            len = atoi(argv[i+1]);
            i++;
            continue;
        }
    }

    if (len % 8 != 0) {
        fprintf(stderr, "Length should be a multiple of 8.\n");
        exit(EXIT_FAILURE);
    }
    len /= 8;

    /* this is where it determines that it's in bytes, could easily be changed
     * to work in bits.  ie: len / 8..  May do that, as when we work with keys
     * we typically think in bits and not in bytes. */
    output = (uint8_t*)malloc(sizeof(uint8_t) * len);

    memset(output, 0, len);
    pbkdf2_hmac_sha256(pass, strlen((const char*)pass), salt,
        strlen((const char*)salt), output, len, c);

    for (i = 0; i < len; ++i) {
        fprintf(stdout, "%02x", output[i]);
    }

    fprintf(stdout, "\n");
    return 0;
}

