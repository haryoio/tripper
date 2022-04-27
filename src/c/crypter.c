#define _GNU_SOURCE

#include<crypt.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define NAMELEN 10

char* crypter (char *key, char *salt) {
    struct crypt_data data;
    data.initialized = 0;

    char* crypted = crypt_r(key, salt, &data);
    return crypted;
}
