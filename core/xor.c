#include <stdio.h>
#include <stdlib.h>

unsigned char* xor_blocks(unsigned char* b1, unsigned char* b2)
{
    unsigned char* buf = (unsigned char*)malloc(32);
    for (int i = 0; i < 32; i++) {
        buf[i] = b1[i] ^ b2[i];
    }
    return buf;
}