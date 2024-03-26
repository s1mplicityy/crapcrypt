#ifndef FILES_H
#define FILES_H

#include <stdio.h>

FILE* fileOpen(char* fileName, char* mode);
int fileSize(FILE* file);
unsigned char* fileRead(FILE* file);
unsigned char* fileReadBytes(FILE* file, int);

#endif