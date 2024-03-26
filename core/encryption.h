#ifndef ENCRYPTION_H
#define ENCRYPTION_H

BlockData ecbEncryptBlocks(BlockData* blocks, unsigned char key[32]);
unsigned char* buildECBCiphertext(BlockData xorredBlocks, int padLen, unsigned char* masterSalt, unsigned char* roundSalts[16]);

#endif