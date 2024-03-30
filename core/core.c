#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utils/data.h"
#include "../utils/files.h"
#include "key.h"
#include "encryption.h"

#define KDF_ITERS 100000

void ecbEncryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md)
{
    BlockData blocks = getBlocks((char*)inputData, fileSize(inputFile));

    // Derive the master key
    DerivedKeyData key = deriveKey(mdctx, md, (unsigned char*)passphrase, strlen(passphrase), NULL, KDF_ITERS);
    printf("ecbEncryptionWrapper: Key = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key.key[i]);
    }
    printf("\n");

    // Expand
    DerivedKeyData* roundKeys = expandKeys(mdctx, md, key.key, 32, NULL, KDF_ITERS);
    unsigned char* roundSalts[16];
    for (int i = 0; i < 16; i++)
    {
        roundSalts[i] = roundKeys[i].salt;
    }

    // Encrypt the blocks
    int padLen = blocks.padLen;
    for (int i = 0; i < 16; i++)
    {
        ecbEncryptBlocks(&blocks, roundKeys[i].key);
    }
    unsigned char* finalCiphertext = buildECBCiphertext(blocks, padLen, key.salt, roundSalts);

    // Save the result into the file
    int bytesWritten = fwrite(finalCiphertext, 1, 20 + 256 + 32 * blocks.blockCount, outputFile);
    printf("ecbEncryptionWrapper: Wrote %d bytes\n", bytesWritten);

    // Cleanup
    _bsFree(&blocks);
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

void ecbDecryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md)
{
    unsigned char* salt = (unsigned char*)malloc(16);
    memcpy(salt, inputData, 16);
    printf("ecbDecryptionWrapper: Salt = ");
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
    char* padLenStr = malloc(4);
    memcpy(padLenStr, inputData + 256 + 16, 4);
    int padLen = atoi( padLenStr );
    printf("ecbDecryptionWrapper: Pad  = %d", padLen);
    printf("\n");

    // Re-derive the key
    DerivedKeyData key = deriveKey(mdctx, md, (unsigned char*)passphrase, strlen(passphrase), (unsigned char*)salt, KDF_ITERS);
    printf("ecbDecryptionWrapper: Key  = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key.key[i]);
    }
    printf("\n");

    // Expand
    DerivedKeyData* roundKeys = expandKeys(mdctx, md, key.key, 32, roundSalts, KDF_ITERS);

    // Split data into blocks
    char* ciphertext = malloc(fileSize(inputFile) - 20 - 256 - padLen);
    memcpy(ciphertext, inputData + 256 + 20, fileSize(inputFile) - 20 - 256 - padLen);
    BlockData ciphertextBlocks = getBlocks(ciphertext, fileSize(inputFile) - 20 - 256 - padLen);


    // Decrypt the blocks
    BlockData xorredBlocks = ciphertextBlocks;
    for (int i = 0; i < 16; i++)
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
    _bsFree(&xorredBlocks);
    free(ciphertext);
    free(plaintext);
}

void cbcEncryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md)
{
    BlockData blocks = getBlocks((char*)inputData, fileSize(inputFile));

    // Derive the master key
    DerivedKeyData key = deriveKey(mdctx, md, (unsigned char*)passphrase, strlen(passphrase), NULL, KDF_ITERS);
    printf("cbcEncryptionWrapper: Key = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key.key[i]);
    }
    printf("\n");

    // Generate the IV
    unsigned char* iv = getIV();
    printf("cbcEncryptionWrapper: IV  = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", iv[i]);
    }
    printf("\n");

    // Expand keys
    DerivedKeyData* roundKeys = expandKeys(mdctx, md, key.key, 32, NULL, KDF_ITERS);

    unsigned char* roundSalts[16];
    for (int i = 0; i < 16; i++)
    {
        roundSalts[i] = roundKeys[i].salt;
    }

    // Encrypt the blocks
    int padLen = blocks.padLen;
    for (int i = 0; i < 16; i++)
    {
        cbcEncryptBlocks(&blocks, iv, roundKeys[i].key);
    }
    unsigned char* finalCiphertext = buildCBCCiphertext(blocks, padLen, key.salt, iv, roundSalts);

    // Save the result into the file
    int bytesWritten = fwrite(finalCiphertext, 1, 20 + 32 + 256 + 32 * blocks.blockCount, outputFile);
    printf("cbcEncryptionWrapper: Wrote %d bytes\n", bytesWritten);

    // Cleanup
    free(key.key);
    free(key.salt);
    free(iv);
    free(finalCiphertext);
    _bsFree(&blocks);
    for (int i = 0; i < 16; i++)
    {
        free(roundKeys[i].key);
        free(roundKeys[i].salt);
    }
    free(roundKeys);
}

void cbcDecryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md)
{
    // Extract metadata
    unsigned char* salt = (unsigned char*)malloc(16);
    unsigned char* iv = (unsigned char*)malloc(32);
    memcpy(salt, inputData, 16);
    printf("cbcDecryptionWrapper: Salt = ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", salt[i]);
    }
    printf("\n");
    memcpy(iv, inputData + 256 + 16, 32);
    printf("cbcDecryptionWrapper: IV   = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", iv[i]);
    }
    printf("\n");
    char* padLenStr = malloc(4);
    memcpy(padLenStr, inputData + 32 + 256 + 16, 4);
    int padLen = atoi( padLenStr );
    printf("cbcDecryptionWrapper: Pad  = %d", padLen);
    printf("\n");
    unsigned char** roundSalts = malloc(16 * sizeof(unsigned char*));
    for (int i = 0; i < 16; i++)
    {
        roundSalts[i] = malloc(16);
        memcpy(roundSalts[i], inputData + 16 + (i*16), 16);
    }

    // Derive the master key
    DerivedKeyData key = deriveKey(mdctx, md, (unsigned char*)passphrase, strlen(passphrase), salt, KDF_ITERS);
    printf("cbcDecryptionWrapper: Key  = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key.key[i]);
    }
    printf("\n");

    // Expand
    DerivedKeyData* roundKeys = expandKeys(mdctx, md, key.key, 32, roundSalts, KDF_ITERS);

    // Split data into blocks
    char* ciphertext = malloc(fileSize(inputFile) - 20 - 32 - 256 - padLen);
    memcpy(ciphertext, inputData + 256 + 32 + 20, fileSize(inputFile) - 20 - 32 - 256 - padLen);
    BlockData blocks = getBlocks(ciphertext, fileSize(inputFile) - 20 - 32 - 256 - padLen);

    // Decrypt the blocks
    for (int i = 0; i < 16; i++)
    {
        cbcDecryptBlocks(&blocks, iv, roundKeys[15-i].key);
    }
    unsigned char* plaintext = join(blocks.blocks, blocks.blockCount);

    // Save the result into the file
    int bytesWritten = fwrite(plaintext, 1, 32 * blocks.blockCount - padLen, outputFile);
    printf("cbcDecryptionWrapper: Wrote %d bytes\n", bytesWritten);

    // Cleanup
    free(key.key);
    free(key.salt);
    free(iv);
    free(ciphertext);
    free(plaintext);
    _bsFree(&blocks);
    free(padLenStr);
    for (int i = 0; i < 16; i++)
    {
        free(roundKeys[i].key);
        free(roundKeys[i].salt);
    }
    free(roundKeys);
    free(roundSalts);
}