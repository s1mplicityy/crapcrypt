#ifndef KEY_H
#define KEY_H

void sha256(const unsigned char *input, size_t inputLen, unsigned char digest);

unsigned char* xjoin(unsigned char** blocks, int* lens, int count);

typedef struct {
    unsigned char* key;
    unsigned char* salt;
} DerivedKeyData;

DerivedKeyData deriveKey(unsigned char* passphrase, size_t passphraseLen, unsigned char* salt, int iters);

DerivedKeyData* expandKeys(unsigned char* passphrase, size_t passphraseLen, unsigned char** roundSalts, int iters);

#endif