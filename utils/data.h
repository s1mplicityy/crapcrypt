#ifndef DATA_H
#define DATA_H

char* slice(const char* str, int start, int end);
char* safeSlice(const char* str, int start, int end);

typedef struct {
    unsigned char** blocks;
    int blockCount;
    int padLen;
} BlockData;
void _bsFree(BlockData* bstruct);
BlockData getBlocks(char* data, int dataLen);

unsigned char* join(unsigned char** blocks, int count);

#endif