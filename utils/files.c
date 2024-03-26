#include <stdio.h>
#include <stdlib.h>

FILE* fileOpen(char* fileName, char* mode)
{
    FILE* file = fopen(fileName, mode);
    if (file == NULL)
    {
        printf("Can't open file: \"%s\"\n", fileName);
        exit(1);
    }
    return file;
}

int fileSize(FILE* file)
{
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);
    rewind(file);
    return fileSize;
}

unsigned char* fileRead(FILE* file)
{
    int fSize = fileSize(file);
    unsigned char* buf = (unsigned char*)malloc(fSize + 1);
    if (buf == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    int bytesRead = fread(buf, 1, fSize, file);
    // printf("fileRead: read %d bytes\n", bytesRead);
    if (bytesRead != fSize)
    {
        printf("Error reading file\n");
        fclose(file);
        free(buf);
        return NULL;
    }
    buf[fSize] = '\0';
    return buf;
}
unsigned char* fileReadBytes(FILE* file, int len)
{
    unsigned char* buf = (unsigned char*)malloc(len + 1);
    if (buf == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    int bytesRead = fread(buf, 1, len, file);
    // printf("fileRead: read %d bytes\n", bytesRead);
    if (bytesRead != len)
    {
        printf("Error reading file\n");
        fclose(file);
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}