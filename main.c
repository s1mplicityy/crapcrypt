#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "utils/data.h"
#include "utils/files.h"
#include "core/key.h"
#include "core/encryption.h"
#include "core/core.h"

int main(int argc, char** argv)
{
    // Init variables
    char* inputFileName = NULL;
    char* outputFileName = NULL;
    char* passphrase = NULL;
    char decrypt = 0;
    char mode = 0;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "m:i:o:p:d")) != -1)
        switch (c)
        {
        case 'm':
            if (!strcmp(optarg, "ecb") || !strcmp(optarg, "ECB")) mode = 1;
            else if (!strcmp(optarg, "cbc") || !strcmp(optarg, "CBC")) mode = 2;
            else printf("Unknown mode '%s'\n", optarg);
            break;
        case 'i':
            inputFileName = optarg;
            break;
        case 'o':
            outputFileName = optarg;
            break;
        case 'p':
            passphrase = optarg;
            break;
        case 'd':
            decrypt = 1;
            break;
        case '?':
            printf("Unknown option '-%c'\n", optopt);
            return 1;
        default:
            printf("Usage: %s -i infile -o outfile -p passphrase [-d] [-u]\n", argv[0]);
            return 1;
        }

    if (!inputFileName || !outputFileName || !passphrase || !mode)
    {
        printf("Usage: %s -m mode(ecb,cbc) -i infile -o outfile -p passphrase [-d]\n", argv[0]);
        return 1;
    }
    if (mode == 1) printf("Note: Using ECB mode (not recommended)\n");

    // Init stuff for hashing
    EVP_MD_CTX* mdctx;
    EVP_MD* md;
    mdctx = EVP_MD_CTX_new();
    md = (EVP_MD*)EVP_sha256();

    // Get initial data
    FILE* inputFile = fileOpen(inputFileName, "rb");
    FILE* outputFile = fileOpen(outputFileName, "wb");
    char* inputData = (char*)fileRead(inputFile);
    
    if (decrypt)
    {
        if (mode == 1)
        {
            // ECB decryption
            if (fileSize(inputFile) < 308)
            {
                printf("Ciphertext file can't be smaller than 340 bytes\n");
                exit(1);
            }
            ecbDecryptionWrapper(inputData, passphrase, inputFile, outputFile, mdctx, md);
        } else
        {
            // CBC decryption
            if (fileSize(inputFile) < 340)
            {
                printf("Ciphertext file can't be smaller than 340 bytes\n");
                exit(1);
            }
            cbcDecryptionWrapper(inputData, passphrase, inputFile, outputFile, mdctx, md);
        }
    }
    else
    {
        if (mode == 1)
        {
            // ECB encryption
            ecbEncryptionWrapper(inputData, passphrase, inputFile, outputFile, mdctx, md);
        } else
        {
            // CBC encryption
            cbcEncryptionWrapper(inputData, passphrase, inputFile, outputFile, mdctx, md);
        }
    }

    
    // Cleanup
    fclose(inputFile);
    fclose(outputFile);
    free(inputData);
    EVP_MD_CTX_free(mdctx);
}
