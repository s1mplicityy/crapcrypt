#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "../utils/files.h"

#define KEY_LEN  32
#define SALT_LEN 16

typedef unsigned char uchar;

void sha256(const uchar *input, size_t inputLen, uchar *output) {
    // I stole this
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, inputLen);
    EVP_DigestFinal_ex(mdctx, output, &md_len);
    EVP_MD_CTX_free(mdctx);
}

unsigned char* xcombine(unsigned char** blocks, int* lens, int count)
{
    int len = 0;
    for (int i = 0; i < count; i++) {
        len += lens[i];
    }
    printf("xcombine: len = %d\n", len);
    uchar* joined = (uchar*)malloc(len);
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
} keyStruct;

keyStruct deriveKey(uchar* passphrase, size_t passphraseLen, uchar* salt, int iters) {
    // The key
    uchar* keyBuf = (uchar*)malloc(KEY_LEN);
    if (keyBuf == NULL) {
        printf("Failed to allocate memory");
        exit(1);
    }
    // Random salt
    if (salt == NULL) {
        salt = (uchar*)malloc(SALT_LEN);
        if (RAND_bytes(salt, SALT_LEN) != 1) {
            printf("Failed to generate salt");
            exit(1);
        }
        // printf("deriveKey: generated salt: %.*s\n", 16, salt);
        printf("deriveKey: generated salt: ");
        for (int i = 0; i < SALT_LEN; i++) printf("%02x", salt[i]);
        printf("\n");
    }

    uchar* blocks[] = {passphrase, salt};
    int blockLens[] = {passphraseLen, SALT_LEN};
    uchar* saltedPass = xcombine(blocks, blockLens, 2);
    sha256(saltedPass, passphraseLen + SALT_LEN, keyBuf);
    for (int i = 0; i < iters - 1; i++) {
        sha256(keyBuf, KEY_LEN, keyBuf);
    }

    // Cleanup
    free(saltedPass);
    
    // Form the struct and return
    keyStruct keyInfo;
    keyInfo.key = keyBuf;
    keyInfo.salt = salt;
    return keyInfo;
}