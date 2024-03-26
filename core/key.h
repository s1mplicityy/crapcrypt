#ifndef KEY_H
#define KEY_H

#include <openssl/evp.h>

void sha256(const unsigned char *input, size_t inputLen, unsigned char digest);

unsigned char* xjoin(unsigned char** blocks, int* lens, int count);

typedef struct {
    unsigned char* key;
    unsigned char* salt;
} DerivedKeyData;

DerivedKeyData deriveKey(EVP_MD_CTX* mdctx, EVP_MD* md, unsigned char* passphrase, size_t passphraseLen, unsigned char* salt, int iters);

DerivedKeyData* expandKeys(EVP_MD_CTX* mdctx, EVP_MD* md, unsigned char* passphrase, size_t passphraseLen, unsigned char** roundSalts, int iters);

#endif