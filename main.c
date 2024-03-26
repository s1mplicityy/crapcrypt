#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>

#include "utils/data.h"
#include "utils/files.h"
#include "core/key.h"
#include "core/encryption.h"

#define MIN_ARGS  4
#define MAX_ARGS  50
#define KDF_ITERS 100000

int main(int argc, char** argv)
{
    if (argc < MIN_ARGS || argc > MAX_ARGS) {
        printf("Invalid argument count (%d), expected %d-%d\n", argc, MIN_ARGS, MAX_ARGS);
        return 0;
    }

    char* inputFileName = NULL;
    char* outputFileName = NULL;
    char* passphrase = NULL;
    char decrypt = 0;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "i:o:p:d")) != -1)
        switch (c)
        {
        case 'i':
            inputFileName = optarg;
            break;
        case 'o':
            outputFileName = optarg;
            break;
        case 'p':
            passphrase = optarg;
            break;
        case 'd':
            decrypt = 1;
            break;
        case '?':
            printf("Unknown option '-%c'\n", optopt);
            return 1;
        default:
            printf("Usage: %s -i infile -o outfile -p passphrase [-d]\n", argv[0]);
            return 1;
        }

    if (!inputFileName || !outputFileName || !passphrase)
    {
        printf("Usage: %s -i infile -o outfile -p passphrase [-d]\n", argv[0]);
        return 1;
    }


    // Get initial data
    FILE* inputFile = fileOpen(inputFileName, "rb");
    FILE* outputFile = fileOpen(outputFileName, "wb");
    unsigned char* inputData = fileRead(inputFile);
    
    if (decrypt)
    {
        // ECB decryption
        unsigned char* salt = (unsigned char*)malloc(16);
        memcpy(salt, inputData, 16);
        printf("(decrypt): Salt = ");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x", salt[i]);
        }
        printf("\n");

        // Extract round salts
        unsigned char** roundSalts = malloc(16 * sizeof(unsigned char*));
        for (int i = 0; i < 16; i++)
        {
            roundSalts[i] = malloc(16);
            memcpy(roundSalts[i], inputData + 16 + (i*16), 16);
        }

        // Extract padding data
        char* padLenStr = slice((char*)inputData, 256 + 16, 256 + 20);
        int padLen = atoi( padLenStr );
        printf("(decrypt): Pad = %d", padLen);
        printf("\n");

        // Re-derive the key
        DerivedKeyData key = deriveKey((unsigned char*)passphrase, strlen(passphrase), (unsigned char*)salt, KDF_ITERS);
        printf("(decrypt): Key = ");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key.key[i]);
        }
        printf("\n");

        // Expand
        DerivedKeyData* roundKeys = expandKeys((unsigned char*)passphrase, strlen(passphrase), roundSalts, KDF_ITERS);

        // Split data into blocks
        char* ciphertext = safeSlice((char*)inputData, 20 + 256, fileSize(inputFile) - padLen);
        BlockData ciphertextBlocks = getBlocks(ciphertext, fileSize(inputFile) - 20 - 256 - padLen);

        // Decrypt the blocks
        BlockData xorredBlocks = ciphertextBlocks;
        for (int i = 1; i < 15; i++)
        {
            ecbEncryptBlocks(&xorredBlocks, roundKeys[i].key);
        }
        unsigned char* plaintext = join(xorredBlocks.blocks, ciphertextBlocks.blockCount);

        // Save the result into the file
        int bytesWritten = fwrite(plaintext, 1, 32 * ciphertextBlocks.blockCount - padLen, outputFile);
        printf("(decrypt): Wrote %d bytes\n", bytesWritten);

        // Cleanup
        free(key.key);
        free(key.salt);
        for (int i = 0; i < 16; i++)
        {
            free(roundKeys[i].key);
            free(roundKeys[i].salt);
        }
        free(roundKeys);
        free(roundSalts);
        free(padLenStr);
        // _bsFree(&ciphertextBlocks);
        _bsFree(&xorredBlocks);
        free(ciphertext);
        free(plaintext);
    }
    else
    {
        // ECB encryption
        BlockData blocks = getBlocks((char*)inputData, fileSize(inputFile));

        // Derive the master key
        DerivedKeyData key = deriveKey((unsigned char*)passphrase, strlen(passphrase), NULL, KDF_ITERS);
        printf("(encrypt): Key = ");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key.key[i]);
        }
        printf("\n");

        // Expand
        DerivedKeyData* roundKeys = expandKeys((unsigned char*)passphrase, strlen(passphrase), NULL, KDF_ITERS);
        unsigned char* roundSalts[16];
        for (int i = 0; i < 16; i++)
        {
            roundSalts[i] = roundKeys[i].salt;
        }

        // Encrypt the blocks
        int padLen = blocks.padLen;
        BlockData xorredBlocks = blocks;
        for (int i = 1; i < 15; i++)
        {
            ecbEncryptBlocks(&xorredBlocks, roundKeys[i].key);
        }
        unsigned char* finalCiphertext = buildECBCiphertext(xorredBlocks, padLen, key.salt, roundSalts);

        // Save the result into the file
        int bytesWritten = fwrite(finalCiphertext, 1, 20 + 256 + 32 * xorredBlocks.blockCount, outputFile);
        printf("(encrypt): Wrote %d bytes\n", bytesWritten);

        // Cleanup
        _bsFree(&xorredBlocks);
        free(finalCiphertext);
        free(key.key);
        free(key.salt);
        for (int i = 0; i < 16; i++)
        {
            free(roundKeys[i].key);
            free(roundKeys[i].salt);
        }
        free(roundKeys);
    }

    
    // Cleanup
    fclose(inputFile);
    fclose(outputFile);
    free(inputData);
}
