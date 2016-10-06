#include <stdio.h>
#include <stdlib.h>

#include <bfcrypt/bfcrypt.h>

void print_usage(const char* name);

int main(int argc, char* argv[])
{
    if (argc == 1) {
        print_usage(argv[0]);
    }
    return 0;
}

void print_usage(const char* name)
{
    fprintf(stdout, "usage:\t$ example -e passphrase input output");
    fprintf(stdout, "\t[encrypt]\n");
    fprintf(stdout, "\t$ example -d passphrase input output");
    fprintf(stdout, "\t[decrypt]\n");
    fprintf(stdout, "\t$ example -i file\t\t\t[verify]\n");
    fprintf(stdout, "\t$ example -b\t\t\t\t[benchmark]\n");
}
