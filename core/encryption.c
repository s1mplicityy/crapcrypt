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
        unsigned char* xorredBlock = xor_blocks(blocks->blocks[i], key);
        memcpy(blocks->blocks[i], xorredBlock, 32);
        free(xorredBlock);
    }
}

unsigned char* buildECBCiphertext(BlockData xorredBlocks, int padLen, unsigned char* masterSalt, unsigned char* roundSalts[16])
{
    unsigned char* ciphertext = join(xorredBlocks.blocks, xorredBlocks.blockCount);
    unsigned char padLenStr[4]; // I got stuck there for three days
    memset(padLenStr, 0, sizeof(padLenStr)); // The only thing I had to do was add this line...
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