#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

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
    FILE *in=fopen(input_file, "rb");
    FILE *out=fopen(output_file,"wb");
    if(in==NULL || out==NULL)
    {
        printf("Error opening files.\n");
        exit(1);
    }
    uint32_t k[4],t[2];
    memcpy(k,key,16); //split key into 4
    uint32_t delta=0x9E3779B9;

    char buffer[8];
    ssize_t bytes;

    uint32_t iv[2] = {0x01234567, 0x89ABCDEF}; // inital values used for CBC mode

   while ((bytes = fread(buffer, 1, 8, in)) > 0) 
    {

        if (bytes < 8) 
        {
            memset(buffer + bytes, 0, 8 - bytes);
        }

        memcpy(t, buffer, 8);

        t[0] ^= iv[0];
        t[1] ^= iv[1];

        uint32_t sum = 0; 
        for (int i = 0; i < 32; i++) // main algorithm loop
        {
            sum += delta;
            t[0] += ((t[1] << 4) + k[0]) ^ (t[1] + sum) ^ ((t[1] >> 5) + k[1]);
            t[1] += ((t[0] << 4) + k[2]) ^ (t[0] + sum) ^ ((t[0] >> 5) + k[3]);
        }

        iv[0] = t[0];
        iv[1] = t[1];

        fwrite(t, 1, 8, out);
    }

    fclose(in);
    fclose(out);


}



void decription(char *input_file, char *output_file, char *key)
{
    FILE *in=fopen(input_file, "rb");
    FILE *out=fopen(output_file,"wb");
    if(in==NULL || out==NULL)
    {
        printf("Error opening files.\n");
        exit(1);
    }
     uint32_t k[4],t[2];
    memcpy(k,key,16);
    uint32_t delta=0x9E3779B9;

    char buffer[8];
    ssize_t bytes;

    uint32_t iv[2] = {0x01234567, 0x89ABCDEF};

   while ((bytes = fread(buffer, 1, 8, in)) > 0) 
    {

        if (bytes < 8) 
        {
            memset(buffer + bytes, 0, 8 - bytes);
        }

        memcpy(t, buffer, 8);

        uint32_t next_iv[2] = {t[0], t[1]};

        uint32_t sum = delta*32; 
        for (int i = 0; i < 32; i++) 
        {
            t[1] -= ((t[0] << 4) + k[2]) ^ (t[0] + sum) ^ ((t[0] >> 5) + k[3]);
            t[0] -= ((t[1] << 4) + k[0]) ^ (t[1] + sum) ^ ((t[1] >> 5) + k[1]);
            sum -= delta;
        }

        t[0] ^= iv[0];
        t[1] ^= iv[1];

        iv[0] = next_iv[0];
        iv[1] = next_iv[1];

        fwrite(t, 1, 8, out);
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
