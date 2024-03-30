#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utils/data.h"
#include "xor.h"
#include "key.h"

void ecbEncryptBlocks(BlockData* blocks, unsigned char key[32])
{
    blocks->padLen = 0;
    for (int i = 0; i < blocks->blockCount; i++)
    {
        if (!blocks->blocks[i]) break;
        xorBlocks(blocks->blocks[i], key);
    }
}

void cbcEncryptBlocks(BlockData* blocks, unsigned char iv[32], unsigned char key[32])
{
    blocks->padLen = 0;
    // Last encrypted block, first time init it with the IV
    unsigned char* lastCiphertextBlock = (unsigned char*)malloc(32);
    memcpy(lastCiphertextBlock, iv, 32);
    for (int i = 0; i < blocks->blockCount; i++)
    {
        xorBlocks(blocks->blocks[i], lastCiphertextBlock);
        xorBlocks(blocks->blocks[i], key);
        memcpy(lastCiphertextBlock, blocks->blocks[i], 32);
    }
    free(lastCiphertextBlock);
}

void cbcDecryptBlocks(BlockData* blocks, unsigned char iv[32], unsigned char key[32])
{
    blocks->padLen = 0;
    // Last ciphertext block, first time init it with the IV
    unsigned char* lastCiphertextBlock = (unsigned char*)malloc(32);
    memcpy(lastCiphertextBlock, iv, 32);
    for (int i = 0; i < blocks->blockCount; i++)
    {
        unsigned char* currentCiphertextBlock = (unsigned char*)malloc(32);
        memcpy(currentCiphertextBlock, blocks->blocks[i], 32);
        xorBlocks(blocks->blocks[i], key);
        xorBlocks(blocks->blocks[i], lastCiphertextBlock);
        memcpy(lastCiphertextBlock, currentCiphertextBlock, 32);
        free(currentCiphertextBlock);
    }
    free(lastCiphertextBlock);
}

unsigned char* buildECBCiphertext(BlockData xorredBlocks, int padLen, unsigned char* masterSalt, unsigned char* roundSalts[16])
{
    unsigned char* ciphertext = join(xorredBlocks.blocks, xorredBlocks.blockCount);
    unsigned char padLenStr[4];
    memset(padLenStr, 0, sizeof(padLenStr));
    snprintf((char*)padLenStr, 4, "%d", padLen);
    unsigned char* finalCipherBlocks[] = {
        masterSalt,
        roundSalts[0],  roundSalts[1],  roundSalts[2],  roundSalts[3],
        roundSalts[4],  roundSalts[5],  roundSalts[6],  roundSalts[7],
        roundSalts[8],  roundSalts[9],  roundSalts[10], roundSalts[11],
        roundSalts[12], roundSalts[13], roundSalts[14], roundSalts[15],
        padLenStr, ciphertext
        };
    int lengths[] = { 16,
        16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16,
        4, 32 * xorredBlocks.blockCount };
    unsigned char* finalCiphertext = xjoin(finalCipherBlocks, lengths, 19);
    free(ciphertext);
    return finalCiphertext;
}

unsigned char* buildCBCCiphertext(BlockData encryptedBlocks, int padLen, unsigned char* salt, unsigned char iv[32], unsigned char* roundSalts[16])
{
    unsigned char* ciphertext = join(encryptedBlocks.blocks, encryptedBlocks.blockCount);
    unsigned char padLenStr[4];
    memset(padLenStr, 0, sizeof(padLenStr));
    snprintf((char*)padLenStr, 4, "%d", padLen);
    unsigned char* finalCipherBlocks[] = {
        salt,
        roundSalts[0],  roundSalts[1],  roundSalts[2],  roundSalts[3],
        roundSalts[4],  roundSalts[5],  roundSalts[6],  roundSalts[7],
        roundSalts[8],  roundSalts[9],  roundSalts[10], roundSalts[11],
        roundSalts[12], roundSalts[13], roundSalts[14], roundSalts[15],
        iv, padLenStr, ciphertext
        };
    int lengths[] = { 16,
        16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16,
        32, 4, 32 * encryptedBlocks.blockCount };
    unsigned char* finalCiphertext = xjoin(finalCipherBlocks, lengths, 20);
    free(ciphertext);
    return finalCiphertext;
}