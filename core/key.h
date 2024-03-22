void sha256(const unsigned char *input, size_t inputLen, unsigned char digest);

unsigned char* xcombine(unsigned char** blocks, int* lens, int count);

typedef struct {
    unsigned char* key;
    unsigned char* salt;
} keyStruct;
keyStruct deriveKey(unsigned char* passphrase, size_t passphraseLen, unsigned char* salt, int iters);