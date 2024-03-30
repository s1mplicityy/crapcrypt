#include <stdio.h>
#include <stdlib.h>

void xorBlocks(unsigned char* b1, unsigned char* b2)
{
    for (int i = 0; i < 32; i++) {
        b1[i] = b1[i] ^ b2[i];
    }
}