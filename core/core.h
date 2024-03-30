#ifndef CORE_H
#define CORE_H

#include "key.h"
#include "encryption.h"

void ecbEncryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md);

void ecbDecryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md);

void cbcEncryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md);

void cbcDecryptionWrapper(char* inputData, char* passphrase, FILE* inputFile, FILE* outputFile, EVP_MD_CTX* mdctx, EVP_MD* md);

#endif