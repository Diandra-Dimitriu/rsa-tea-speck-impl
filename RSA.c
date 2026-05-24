#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <gmp.h>

#define MAX_BLOCK_SIZE 64

void read_keys(const char *filename, char **p_str, char **q_str)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        perror("Error opening key file");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = (char *)malloc(fsize + 1);
    if (buffer == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }

    fread(buffer, 1, fsize, f);
    buffer[fsize] = '\0';
    fclose(f);

    char *src = buffer, *dst = buffer;
    while (*src) {
        if (*src != '\r') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';

    char *sep = strstr(buffer, "\n\n");
    if (sep == NULL) {
        fprintf(stderr, "Error\n");
        free(buffer);
        exit(1);
    }

    *sep = '\0';
    *p_str = strdup(buffer);

    char *q_start = sep + 2;
    while (*q_start == '\n') {
        q_start++;
    }

    *q_str = strdup(q_start);
    char *q_end = *q_str + strlen(*q_str) - 1;
    while (q_end >= *q_str && *q_end == '\n') {
        *q_end = '\0';
        q_end--;
    }

    free(buffer);
}

void key_gen(char *p_str, char *q_str, mpz_t e, mpz_t d, mpz_t n)
{
    mpz_t p, q, p_next, q_next, coprime_n, p_minus_1, q_minus_1;
    mpz_inits(p, q, p_next, q_next, coprime_n, p_minus_1, q_minus_1, NULL);

    mpz_set_str(p, p_str, 10);
    mpz_set_str(q, q_str, 10);

    mpz_nextprime(p_next, p);
    mpz_nextprime(q_next, q);

    mpz_mul(n, p_next, q_next);

    mpz_sub_ui(p_minus_1, p_next, 1);
    mpz_sub_ui(q_minus_1, q_next, 1);
    mpz_mul(coprime_n, p_minus_1, q_minus_1);
    mpz_invert(d, e, coprime_n);

    mpz_clears(p, q, p_next, q_next, coprime_n, p_minus_1, q_minus_1, NULL);
}

void encription(char *input_file, char *output_file, char *p_str, char *q_str)
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if(in == NULL || out == NULL) {
        printf("Error opening files.\n");
        exit(1);
    }

    mpz_t n, d, e, m, c;
    mpz_inits(n, d, e, m, c, NULL);
    mpz_set_ui(e, 65537);
    key_gen(p_str, q_str, e, d, n);

    char buffer[MAX_BLOCK_SIZE];
    size_t bytes;

    size_t block_limit = (mpz_sizeinbase(n, 2) - 1) / 8; // make sure block size is less than n
    if (block_limit > sizeof(buffer)) {
        block_limit = sizeof(buffer);
    }
    if (block_limit == 0) {
        printf("RSA key is too small.\n");
        exit(1);
    }

    while ((bytes = fread(buffer, 1, block_limit, in)) > 0)
    {
        unsigned char block_size = (unsigned char)bytes; // store actual block size for proper decryption
        mpz_import(m, bytes, 1, sizeof(char), 0, 0, buffer);
        mpz_powm(c, m, e, n);

        fwrite(&block_size, 1, 1, out);
        mpz_out_raw(out, c);
    }

    mpz_clears(n, d, e, m, c, NULL);
    fclose(in);
    fclose(out);
}

void decription(char *input_file, char *output_file, char *p_str, char *q_str)
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if(in == NULL || out == NULL) {
        printf("Error opening files.\n");
        exit(1);
    }

    mpz_t n, d, e, m, c;
    mpz_inits(n, d, e, m, c, NULL);
    mpz_set_ui(e, 65537);
    key_gen(p_str, q_str, e, d, n);

    char buffer[MAX_BLOCK_SIZE];
    char fixed_buffer[MAX_BLOCK_SIZE];
    size_t bytes;
    unsigned char block_size;

    while (fread(&block_size, 1, 1, in) == 1)
    {
        if (block_size == 0 || block_size > sizeof(fixed_buffer)) {
            printf("Encrypted file has an invalid block size.\n");
            exit(1);
        }

        if (mpz_inp_raw(c, in) == 0) {
            printf("Encrypted file is damaged or incomplete.\n");
            exit(1);
        }

        mpz_powm(m, c, d, n);
        mpz_export(buffer, &bytes, 1, sizeof(char), 0, 0, m);

        if (bytes > block_size) {
            printf("Decryption error: recovered block is too large.\n");
            exit(1);
        }

        memset(fixed_buffer, 0, block_size);
        memcpy(fixed_buffer + (block_size - bytes), buffer, bytes); // right-align the decrypted block
        fwrite(fixed_buffer, 1, block_size, out);
    }

    mpz_clears(n, d, e, m, c, NULL);
    fclose(in);
    fclose(out);
}

int main(int argc, char **argv)
{
    int out=0, e_flag=0, d_flag=0;
    char *input_file=NULL, *output_file=NULL, *key_file=NULL;
    char *p_str=NULL, *q_str=NULL;

    for (int i=1; i<argc; i++)
    {
        if (strcmp(argv[i],"-e")==0) e_flag=1;
        else if (strcmp(argv[i],"-d")==0) d_flag=1;
        else if (strcmp(argv[i],"-o")==0 && out==0)
        {
            if (i+1<argc) {
                output_file = argv[i+1];
                out = 1;
                i++;
            } else {
                perror("No output file given");
                return 1;
            }
        }
        else if (strcmp(argv[i],"-k")==0)
        {
            if (i+1<argc) {
                key_file = argv[i+1];
                i++;
            } else {
                perror("No key file given");
                return 1;
            }
        }
        else {
            input_file = argv[i];
        }
    }

    if (key_file == NULL) {
        fprintf(stderr, "Missing key file argument (-k <filename>)\n");
        return 1;
    }

    read_keys(key_file, &p_str, &q_str);

    if (e_flag==1 && out==1 && input_file!=NULL) {
        encription(input_file, output_file, p_str, q_str);
    }
    else if (d_flag==1 && out==1 && input_file!=NULL) {
        decription(input_file, output_file, p_str, q_str);
    }
    else {
        fprintf(stderr, "Argument input wrong\n");
        free(p_str);
        free(q_str);
        return 1;
    }

    free(p_str);
    free(q_str);
    return 0;
}