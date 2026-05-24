#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#define ROR(x, r) (((x) >> (r)) | ((x) << (32 - (r)))) // rotate right
#define ROL(x, r) (((x) << (r)) | ((x) >> (32 - (r)))) // rotate left

char* read_key(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        perror("Error opening key file");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    long alloc_size = (fsize > 16) ? (fsize + 1) : 17;
    
    char *buffer = (char *)calloc(alloc_size, sizeof(char));
    if (buffer == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }

    fread(buffer, 1, fsize, f);
    fclose(f);

    char *src = buffer;
    char *dst = buffer;
    
    while (*src != '\0') {
        if (*src != '\r' && *src != '\n') {
            *dst = *src;
            dst++;
        }
        src++;
    }
    
    *dst = '\0'; 

    return buffer;
}

void encription(char *input_file, char *output_file, char *key)
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if(in == NULL || out == NULL)
    {
        printf("Error opening files.\n");
        exit(1);
    }
    
    uint32_t x, y, k[4];
    memcpy(k, key, 16);
    uint32_t k_m = k[0]; // key split
    uint32_t l[3] = {k[1], k[2], k[3]};

    uint32_t alpha = 8, beta = 3;

    char buffer[8];
    ssize_t bytes;

    uint32_t round_keys[27];
    for (int i = 0; i < 27; i++) { // key schedule generation
        round_keys[i] = k_m;
        uint32_t new_l = (ROR(l[i % beta], alpha) + k_m) ^ i; 
        k_m = ROL(k_m, beta) ^ new_l;
        l[i % beta] = new_l;
    }

    uint32_t iv[2] = {0x01234567, 0x89ABCDEF}; // initial values for CBC mode

    while ((bytes = fread(buffer, 1, 8, in)) > 0) 
    {
        if (bytes < 8) 
        {
            memset(buffer + bytes, 0, 8 - bytes);
        }

        memcpy(&x, buffer, 4);
        memcpy(&y, buffer + 4, 4);

        x ^= iv[0];
        y ^= iv[1];

        for (int i = 0; i < 27; i++)  // main encryption loop
        {
            x = (ROR(x, 8) + y) ^ round_keys[i];
            y = ROL(y, 3) ^ x;
        }

        iv[0] = x;
        iv[1] = y;

        memcpy(buffer, &x, 4);
        memcpy(buffer + 4, &y, 4);
        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
}

void decription(char *input_file, char *output_file, char *key)
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if(in == NULL || out == NULL)
    {
        printf("Error opening files.\n");
        exit(1);
    }
    
    uint32_t x, y, k[4];
    memcpy(k, key, 16);
    uint32_t k_m = k[0];
    uint32_t l[3] = {k[1], k[2], k[3]};

    uint32_t alpha = 8, beta = 3;

    char buffer[8];
    ssize_t bytes;

    uint32_t round_keys[27];
    for (int i = 0; i < 27; i++) {
        round_keys[i] = k_m;
        uint32_t new_l = (ROR(l[i % beta], alpha) + k_m) ^ i; 
        k_m = ROL(k_m, beta) ^ new_l;
        l[i % beta] = new_l;
    }

    uint32_t iv[2] = {0x01234567, 0x89ABCDEF};

    while ((bytes = fread(buffer, 1, 8, in)) > 0) 
    {
        if (bytes < 8) 
        {
            memset(buffer + bytes, 0, 8 - bytes);
        }

        memcpy(&x, buffer, 4);
        memcpy(&y, buffer + 4, 4);

        uint32_t next_iv[2] = {x, y};

        for (int i = 26; i >= 0; i--) 
        {
            y = ROR(y ^ x, 3);
            x = ROL((x ^ round_keys[i]) - y, 8);
        }

        x ^= iv[0];
        y ^= iv[1];

        iv[0] = next_iv[0];
        iv[1] = next_iv[1];

        memcpy(buffer, &x, 4);
        memcpy(buffer + 4, &y, 4);
        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
}

int main(int argc, char **argv)
{
    int out = 0, e = 0, d = 0;
    char *input_file = NULL, *output_file = NULL, *key_file = NULL;
    char *key_str = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-e") == 0)
        {
            e = 1;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            d = 1;
        }
        else if (strcmp(argv[i], "-o") == 0 && out == 0)
        {
            if (i + 1 < argc)
            {
                output_file = argv[i + 1];
                out = 1;
                i++;
            }
            else
            {
                perror("No output file given");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            if (i + 1 < argc)
            {
                key_file = argv[i + 1];
                i++;
            }
            else
            {
                perror("No key file given");
                return 1;
            }
        }
        else
        {
            input_file = argv[i];
        }
    }

    if (key_file == NULL) {
        fprintf(stderr, "Missing key file argument (-k <filename>)\n");
        return 1;
    }
    key_str = read_key(key_file);

    if (e == 1 && out == 1 && input_file != NULL)
    {
        encription(input_file, output_file, key_str);
    }
    else if (d == 1 && out == 1 && input_file != NULL)
    {
        decription(input_file, output_file, key_str);
    }
    else 
    {
        perror("Argument input wrong");
        free(key_str);
        return 1;
    }

    free(key_str);
    return 0;
}