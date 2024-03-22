char* slice(const char* str, int start, int end);
char* safeSlice(const char* str, int start, int end);

typedef struct {
    unsigned char** blocks;
    int blockCount;
    int padLen;
} blocksStruct;
void _bsFree(blocksStruct* bstruct);
blocksStruct getBlocks(char* data, int dataLen);

unsigned char* combine(unsigned char** blocks, int count);