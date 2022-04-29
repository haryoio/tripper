#define _GNU_SOURCE

#include<crypt.h>

#define NAMELEN 10

char* crypter (char *key, char *salt) {
    struct crypt_data data;
    data.initialized = 0;

    char* crypted = crypt_r(key, salt, &data);
    return crypted;
}
