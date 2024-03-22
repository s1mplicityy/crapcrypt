#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utils/data.h"
#include "xor.h"

blocksStruct ecbEncryptBlocks(blocksStruct* plain, unsigned char key[32])
{
    blocksStruct xorredBlocksStruct;
    xorredBlocksStruct.blockCount = plain->blockCount;
    xorredBlocksStruct.blocks = (unsigned char**)malloc(plain->blockCount * sizeof(unsigned char*));
    if (xorredBlocksStruct.blocks == NULL) {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    for (int i = 0; i < plain->blockCount; i++) {
        unsigned char* xorredBlock = xor_blocks(plain->blocks[i], key);
        // printf("ecbEncryptBlocks: %.*s\n", 32, xorredBlock);
        // printf("%.*s ^ ", 32, plain.blocks[i]);
        // for (int t = 0; t < 32; t++) printf("%02x", key[t]);
        // printf(" = ");
        // for (int t = 0; t < 32; t++) printf("%02x", xorredBlock[t]);
        // printf("\n");
        xorredBlocksStruct.blocks[i] = (unsigned char*)malloc(32);
        memcpy(xorredBlocksStruct.blocks[i], xorredBlock, 32);
        free(xorredBlock);
    }
    return xorredBlocksStruct;
}