#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils/files.h"
#include "utils/data.h"
#include "core/xor.h"
#include "core/key.h"
#include "core/encryption.h"

#define MIN_ARGS 4
#define MAX_ARGS 5

typedef unsigned char uchar;

int main(int argc, char** argv)
{
    if (argc < MIN_ARGS || argc > MAX_ARGS) {
        printf("Invalid argument count (%d), expected %d-%d\n", argc, MIN_ARGS, MAX_ARGS);
        return 0;
    }

    // Get initial data
    FILE* inputFile = fileOpen(argv[1], "rb");
    FILE* outputFile = fileOpen(argv[2], "wb");
    unsigned char* inputData = fileRead(inputFile);
    
    // ECB encryption
    if (strcmp(argv[4], "-d")) {
        // Divide data into blocks
        blocksStruct blocks = getBlocks((char*)inputData, fileSize(inputFile));

        // Derive the master key
        keyStruct key = deriveKey((uchar*)argv[3], strlen(argv[3]), NULL, 100*1000);
        printf("main (encrypt): Key = ");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key.key[i]);
        }
        printf("\n");

        // Encrypt the blocks
        blocksStruct xorredBlocks = ecbEncryptBlocks(&blocks, key.key);
        uchar* ciphertext = combine(xorredBlocks.blocks, blocks.blockCount);
        uchar padLenStr[4];
        sprintf((char*)padLenStr, "%d", blocks.padLen);
        uchar* finalCipherBlocks[] = { key.salt, padLenStr, ciphertext };
        int lengths[] = { 16, 4, 32 * blocks.blockCount };
        uchar* finalCiphertext = xcombine(finalCipherBlocks, lengths, 3);

        // Save the result into the file
        int bytesWritten = fwrite(finalCiphertext, 1, 20 + 32 * blocks.blockCount, outputFile);
        printf("main (encrypt): Wrote %d bytes\n", bytesWritten);

        // Cleanup
        _bsFree(&xorredBlocks);
        free(ciphertext);
        free(finalCiphertext);
        _bsFree(&blocks);
        free(key.key);
        free(key.salt);
    } else {
        // ECB decryption
        uchar* salt = (uchar*)slice((char*)inputData, 0, 16);
        printf("main (decrypt): Salt = ");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x", salt[i]);
        }
        printf("\n");

        char* padLenStr = slice((char*)inputData, 16, 20);
        int padLen = atoi( padLenStr );
        printf("main (decrypt): Pad = %d", padLen);
        printf("\n");

        // Re-derive the key
        keyStruct key = deriveKey((uchar*)argv[3], strlen(argv[3]), (uchar*)salt, 100 * 1000);
        printf("main (decrypt): Key = ");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key.key[i]);
        }
        printf("\n");

        // Split data into blocks, decrypt them
        char* ciphertext = safeSlice((char*)inputData, 20, fileSize(inputFile) - padLen);
        blocksStruct ciphertextBlocks = getBlocks(ciphertext, fileSize(inputFile) - 20 - padLen);
        blocksStruct xorredBlocks = ecbEncryptBlocks(&ciphertextBlocks, key.key);
        uchar* plaintext = combine(xorredBlocks.blocks, ciphertextBlocks.blockCount);

        // Save the result into the file
        int bytesWritten = fwrite(plaintext, 1, 32 * ciphertextBlocks.blockCount - padLen, outputFile);
        printf("main (decrypt): Wrote %d bytes\n", bytesWritten);

        // Cleanup
        free(key.key);
        free(key.salt);
        free(padLenStr);
        _bsFree(&ciphertextBlocks);
        _bsFree(&xorredBlocks);
        free(ciphertext);
        free(plaintext);
    }

    
    // Cleanup
    fclose(inputFile);
    fclose(outputFile);
    free(inputData);
}