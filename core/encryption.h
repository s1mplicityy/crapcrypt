#ifndef ENCRYPTION_H
#define ENCRYPTION_H

BlockData ecbEncryptBlocks(BlockData* blocks, unsigned char key[32]);
void cbcEncryptBlocks(BlockData* blocks, unsigned char iv[32], unsigned char key[32]);
void cbcDecryptBlocks(BlockData* blocks, unsigned char iv[32], unsigned char key[32]);
unsigned char* buildECBCiphertext(BlockData xorredBlocks, int padLen, unsigned char* masterSalt, unsigned char* roundSalts[16]);
unsigned char* buildCBCCiphertext(BlockData encryptedBlocks, int padLen, unsigned char* salt, unsigned char iv[32], unsigned char* roundSalts[16]);

#endif