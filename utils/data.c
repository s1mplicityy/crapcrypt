#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* slice(const char* str, int start, int end)
{
    int slice_length = end - start;
    char* sliced_str = (char*)malloc(slice_length);
    if (sliced_str == NULL) {
        printf("Memory allocation failed");
        exit(1);
    }
    strncpy(sliced_str, str + start, slice_length);
    // memcpy(sliced_str, str + start, slice_length);
    return sliced_str;
}

char* safeSlice(const char* str, int start, int end)
{
    int slice_length = end - start;
    char* sliced_str = (char*)malloc(slice_length + 1);
    if (sliced_str == NULL) {
        printf("Memory allocation failed");
        exit(1);
    }
    strncpy(sliced_str, str + start, slice_length);
    sliced_str[slice_length] = '\0';
    return sliced_str;
}

char* _pad(char* data, int offset, int padLen)
{
    for (int i = 0; i < padLen; i++) {
        data[i + offset] = padLen;
    }
    return data;
}

typedef struct {
    char** blocks;
    int blockCount;
    int padLen;
} BlockData;
void _bsFree(BlockData* bstruct)
{
    for (int i = 0; i < bstruct->blockCount; i++) {
        free(bstruct->blocks[i]);
    }
    free(bstruct->blocks);
} 

BlockData getBlocks(char* data, int dataLen)
{
    // Gather data
    int leftover = dataLen % 32;
    int pad = 32 - leftover;
    int blockCount = dataLen / 32;
    // If data len is not multiple of 32, add one more block
    if (leftover != 0) blockCount++;
    // Init blockstruct
    BlockData bs;
    bs.blocks = (char**)malloc(blockCount * sizeof(char*));
    if (bs.blocks == NULL) {
        printf("Memory allocation failed");
        exit(1);
    }
    // printf("getBlocks: %d bytes of data, %d blocks, %d bytes left, %d bytes pad\n", dataLen, blockCount, leftover, pad);
    // Blocks will be stored here
    // Split the data into blocks
    for (int i = 0; i < blockCount - 1; i++) {
        bs.blocks[i] = (char*)malloc(32);
        char* chunk = slice(data, i*32, i*32+32);
        memcpy(bs.blocks[i], chunk, 32);
        free(chunk);
        // printf("getBlocks: blocks[%d] = %.*s\n", i, 32, bs.blocks[i]);
    }
    // Pad the last block if necessary
    if (leftover != 0) {
        char* leftoverChunk = slice(data,
            (blockCount - 1) * 32,
            (blockCount * 32));
        char* paddedLeftover = _pad(leftoverChunk, leftover, pad);
        bs.blocks[blockCount - 1] = (char*)malloc(32 + 1);
        if (bs.blocks[blockCount - 1] == NULL) {
            printf("Memory allocation failed\n");
            exit(-1);
        }
        memcpy(bs.blocks[blockCount - 1], paddedLeftover, 32);
        free(leftoverChunk);
        // printf("getBlocks: paddedLeftover = %.*s\n", 32, bs.blocks[blockCount - 1]);
    }
    // Finish the struct and return
    bs.blockCount = blockCount;
    bs.padLen = pad;
    return bs;
}

unsigned char* join(const unsigned char** blocks, int count)
{
    int len = 32 * count;
    // printf("join: len = %d\n", len);
    unsigned char* joined = (unsigned char*)malloc(len);
    if (joined == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    for (int i = 0; i < count; i++) {
        memcpy(joined + i*32, blocks[i], 32);
    }
    // printf("join: %.*s\n", len, joined);
    return joined;
}