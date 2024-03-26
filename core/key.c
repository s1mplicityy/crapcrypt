#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define KEY_LEN   32
#define SALT_LEN  16

void sha256(EVP_MD_CTX* mdctx, EVP_MD* md, const unsigned char *input, size_t inputLen, unsigned char *output)
{
    // I stole this
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, inputLen);
    EVP_DigestFinal_ex(mdctx, output, &md_len);
}

unsigned char* xjoin(unsigned char** blocks, int* lens, int count)
{
    int len = 0;
    for (int i = 0; i < count; i++) {
        len += lens[i];
    }
    // printf("xjoin: len = %d\n", len);
    unsigned char* joined = (unsigned char*)malloc(len);
    if (joined == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    int cursorPos = 0;
    for (int i = 0; i < count; i++) {
        memcpy(joined + cursorPos, blocks[i], lens[i]);
        cursorPos += lens[i];
    }
    return joined;
}

typedef struct {
    unsigned char* key;
    unsigned char* salt;
} DerivedKeyData;

DerivedKeyData deriveKey(EVP_MD_CTX* mdctx, EVP_MD* md, unsigned char* passphrase, size_t passphraseLen, unsigned char* salt, int iters)
{
    // The key
    unsigned char* keyBuf = (unsigned char*)malloc(KEY_LEN);
    if (keyBuf == NULL)
    {
        printf("Failed to allocate memory");
        exit(1);
    }
    // Random salt
    if (salt == NULL)
    {
        salt = (unsigned char*)malloc(SALT_LEN);
        if (RAND_bytes(salt, SALT_LEN) != 1) {
            printf("Failed to generate salt");
            exit(1);
        }
        // printf("deriveKey: generated salt: ");
        // for (int i = 0; i < SALT_LEN; i++) printf("%02x", salt[i]);
        // printf("\n");
    }
    // printf("deriveKey: using salt: ");
    // for (int i = 0; i < SALT_LEN; i++) printf("%02x", salt[i]);
    // printf("\n");

    unsigned char* blocks[] = {passphrase, salt};
    int blockLens[] = {passphraseLen, SALT_LEN};
    unsigned char* saltedPass = xjoin(blocks, blockLens, 2);
    sha256(mdctx, md, saltedPass, passphraseLen + SALT_LEN, keyBuf);
    for (int i = 0; i < iters - 1; i++)
    {
        sha256(mdctx, md, keyBuf, KEY_LEN, keyBuf);
    }
    // printf("deriveKey: derived key: ");
    // for (int i = 0; i < KEY_LEN; i++) printf("%02x", keyBuf[i]);
    // printf("\n");

    // Cleanup
    free(saltedPass);
    
    // Form the struct and return
    DerivedKeyData keyInfo;
    keyInfo.key = keyBuf;
    keyInfo.salt = salt;
    return keyInfo;
}

DerivedKeyData* expandKeys(EVP_MD_CTX* mdctx, EVP_MD* md, unsigned char* passphrase, size_t passphraseLen, unsigned char** roundSalts, int iters)
{
    DerivedKeyData* keys = malloc(16 * sizeof(DerivedKeyData));
    for (int i = 0; i < 16; i++)
    {
        DerivedKeyData key;
        if (roundSalts != NULL)
        {
            key = deriveKey(mdctx, md, passphrase, passphraseLen, roundSalts[i], iters);
        }
        else
        {
            key = deriveKey(mdctx, md, passphrase, passphraseLen, NULL, iters);
        }
        keys[i] = key;
    }
    return keys;
}